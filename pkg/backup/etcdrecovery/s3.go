// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package etcdrecovery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

const maximumVersionListingBytes = 1 << 20

type s3Credentials struct {
	accessKey    []byte
	secretKey    []byte
	sessionToken []byte
}

func (credentials *s3Credentials) clear() {
	if credentials == nil {
		return
	}
	clear(credentials.accessKey)
	clear(credentials.secretKey)
	clear(credentials.sessionToken)
}

type s3VersionListing struct {
	XMLName     xml.Name `xml:"ListVersionsResult"`
	IsTruncated bool     `xml:"IsTruncated"`
	Versions    []struct {
		Key       string `xml:"Key"`
		VersionID string `xml:"VersionId"`
		Size      int64  `xml:"Size"`
	} `xml:"Version"`
}

// ResolveS3ObjectVersion resolves one exact immutable S3-compatible object
// version by its source-safe SHA-256 binding. Credentials and the raw version
// remain caller-owned protected data and are never included in returned
// errors. A truncated or ambiguous listing fails closed.
func ResolveS3ObjectVersion(
	ctx context.Context,
	lookup S3ObjectVersionLookup,
	sharedCredentials []byte,
	now time.Time,
) (string, error) {
	return resolveS3ObjectVersionWithClient(ctx, lookup, sharedCredentials, now, newS3Client())
}

func resolveS3ObjectVersionWithClient(
	ctx context.Context,
	lookup S3ObjectVersionLookup,
	sharedCredentials []byte,
	now time.Time,
	client *http.Client,
) (string, error) {
	if ctx == nil || client == nil || !validS3VersionLookup(lookup) || now.IsZero() {
		return "", errors.New("S3 object version lookup is invalid")
	}
	credentials, err := parseSharedS3Credentials(sharedCredentials)
	if err != nil {
		return "", errors.New("S3 object version credentials are unavailable")
	}
	defer credentials.clear()
	endpoint, err := parseS3Endpoint(lookup.Endpoint)
	if err != nil {
		return "", errors.New("S3 object version endpoint is invalid")
	}
	canonicalURI := "/" + awsEscape(lookup.Bucket)
	canonicalQuery := "max-keys=1000&prefix=" + awsEscape(lookup.ObjectKey) + "&versions="
	endpoint.Path = "/" + lookup.Bucket
	endpoint.RawPath = canonicalURI
	endpoint.RawQuery = canonicalQuery
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", errors.New("create S3 object version lookup")
	}
	request.Header.Set("Accept", "application/xml")
	request.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	if err := signS3Request(request, lookup.Region, canonicalURI, canonicalQuery, now.UTC(), credentials); err != nil {
		return "", errors.New("sign S3 object version lookup")
	}
	safeClient := *client
	safeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := safeClient.Do(request)
	request.Header.Del("Authorization")
	request.Header.Del("X-Amz-Security-Token")
	if err != nil {
		return "", errors.New("query S3 object versions")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		response.ContentLength > maximumVersionListingBytes {
		return "", errors.New("S3 object version response is invalid")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximumVersionListingBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumVersionListingBytes {
		clear(payload)
		return "", errors.New("read bounded S3 object version response")
	}
	defer clear(payload)
	var listing s3VersionListing
	if xml.Unmarshal(payload, &listing) != nil || listing.XMLName.Local != "ListVersionsResult" ||
		listing.IsTruncated || len(listing.Versions) == 0 || len(listing.Versions) > 1000 {
		return "", errors.New("S3 object version listing is invalid or incomplete")
	}
	resolved := ""
	for _, version := range listing.Versions {
		if version.Key != lookup.ObjectKey || version.Size != lookup.ExpectedBytes ||
			!safeOpaque(version.VersionID, 512) ||
			sha256Hex([]byte(version.VersionID)) != lookup.ObjectVersionSHA256 {
			continue
		}
		if resolved != "" {
			return "", errors.New("S3 object version binding is ambiguous")
		}
		resolved = version.VersionID
	}
	if resolved == "" {
		return "", errors.New("S3 object version binding was not found")
	}
	return resolved, nil
}

func validS3VersionLookup(lookup S3ObjectVersionLookup) bool {
	_, err := parseS3Endpoint(lookup.Endpoint)
	return err == nil && safeS3Region(lookup.Region) && safeS3Bucket(lookup.Bucket) &&
		validObjectKey(lookup.ObjectKey) && validSHA256(lookup.ObjectVersionSHA256) &&
		lookup.ExpectedBytes > 0 && lookup.ExpectedBytes <= MaxArchiveBytes
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func validSource(request Request) bool {
	switch request.SourceMode {
	case "local-file":
		return request.Endpoint == "" && request.Region == "" && request.Bucket == "" &&
			request.ObjectKey == "" && request.ObjectVersion == ""
	case "s3":
		_, err := parseS3Endpoint(request.Endpoint)
		return err == nil && safeS3Region(request.Region) && safeS3Bucket(request.Bucket) &&
			validObjectKey(request.ObjectKey) && safeOpaque(request.ObjectVersion, 512)
	default:
		return false
	}
}

func safeS3Region(value string) bool {
	if value == "" || len(value) > 63 || value != strings.ToLower(value) ||
		value[0] < 'a' && (value[0] < '0' || value[0] > '9') ||
		value[len(value)-1] < 'a' && (value[len(value)-1] < '0' || value[len(value)-1] > '9') {
		return false
	}
	for _, character := range value {
		if character != '-' && character != '.' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func safeS3Bucket(value string) bool {
	return safeID(value) && len(value) >= 3 && len(value) <= 63
}

func fetchS3Archive(ctx context.Context, request Request, credentialRoot, workspace string, now time.Time) (*protectedFile, error) {
	return fetchS3ArchiveWithClient(ctx, request, credentialRoot, workspace, now, newS3Client())
}

func newS3Client() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   1,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func fetchS3ArchiveWithClient(ctx context.Context, request Request, credentialRoot, workspace string, now time.Time, client *http.Client) (*protectedFile, error) {
	if ctx == nil || client == nil || request.SourceMode != "s3" || !validSource(request) || !filepath.IsAbs(workspace) {
		return nil, errors.New("S3 recovery input is invalid")
	}
	credentials, err := readS3Credentials(ctx, credentialRoot)
	if err != nil {
		return nil, errors.New("S3 recovery credentials are unavailable")
	}
	defer credentials.clear()
	objectURL, canonicalURI, canonicalQuery, err := s3ObjectURL(request)
	if err != nil {
		return nil, errors.New("S3 recovery object URL is invalid")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, objectURL.String(), nil)
	if err != nil {
		return nil, errors.New("create S3 recovery request")
	}
	httpRequest.Header.Set("Accept", "application/octet-stream")
	httpRequest.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	if err := signS3Request(httpRequest, request.Region, canonicalURI, canonicalQuery, now.UTC(), credentials); err != nil {
		return nil, errors.New("sign S3 recovery request")
	}
	safeClient := *client
	safeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := safeClient.Do(httpRequest)
	httpRequest.Header.Del("Authorization")
	httpRequest.Header.Del("X-Amz-Security-Token")
	if err != nil {
		return nil, errors.New("fetch S3 recovery object")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength != request.SnapshotBytes ||
		response.Header.Get("X-Amz-Version-Id") != request.ObjectVersion {
		return nil, errors.New("S3 recovery object identity is invalid")
	}
	archivePath := filepath.Join(workspace, "archive.db")
	// #nosec G304 -- archivePath is the fixed name beneath the fresh private workspace.
	archive, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.New("create private S3 recovery archive")
	}
	complete := false
	defer func() {
		if !complete {
			_ = archive.Close()
			_ = os.Remove(archivePath)
		}
	}()
	hasher := sha256.New()
	reader := &contextReader{ctx: ctx, reader: io.LimitReader(response.Body, request.SnapshotBytes+1)}
	buffer := make([]byte, 128<<10)
	written, copyErr := io.CopyBuffer(io.MultiWriter(archive, hasher), reader, buffer)
	clear(buffer)
	syncErr := archive.Sync()
	closeErr := archive.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != request.SnapshotBytes ||
		hex.EncodeToString(hasher.Sum(nil)) != request.SnapshotChecksumSHA256 {
		return nil, errors.New("S3 recovery object content is invalid")
	}
	complete = true
	opened, err := openProtectedFile(archivePath, MaxArchiveBytes, exactOwnerOnly)
	if err != nil {
		_ = os.Remove(archivePath)
		return nil, errors.New("open private S3 recovery archive")
	}
	return opened, nil
}

func readS3Credentials(ctx context.Context, root string) (*s3Credentials, error) {
	values, err := readProjectedSetContext(
		ctx,
		root,
		[]string{SharedCredentialsKey},
		nil,
		maximumCredentialBytes,
	)
	if err != nil {
		return nil, errors.New("S3 access key is invalid")
	}
	payload := values[SharedCredentialsKey]
	credentials, parseErr := parseSharedS3Credentials(payload)
	for _, value := range values {
		clear(value)
	}
	if parseErr != nil {
		return nil, errors.New("S3 access key is invalid")
	}
	return credentials, nil
}

func parseSharedS3Credentials(payload []byte) (*s3Credentials, error) {
	if len(payload) == 0 || len(payload) > maximumCredentialBytes || bytes.IndexByte(payload, 0) >= 0 {
		return nil, errors.New("shared S3 credentials are invalid")
	}
	var accessIdentifier, secretKey, sessionToken []byte
	sectionSeen := false
	seen := map[string]bool{}
	lines := bytes.Split(payload, []byte{'\n'})
	if len(lines) > 32 {
		return nil, errors.New("shared S3 credentials are invalid")
	}
	for _, rawLine := range lines {
		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			if sectionSeen || !bytes.Equal(line, []byte("[default]")) {
				clear(accessIdentifier)
				clear(secretKey)
				clear(sessionToken)
				return nil, errors.New("shared S3 credentials are invalid")
			}
			sectionSeen = true
			continue
		}
		if !sectionSeen {
			clear(accessIdentifier)
			clear(secretKey)
			clear(sessionToken)
			return nil, errors.New("shared S3 credentials are invalid")
		}
		key, value, found := bytes.Cut(line, []byte{'='})
		key = bytes.TrimSpace(key)
		value = bytes.TrimSpace(value)
		keyText := string(key)
		if !found || len(value) == 0 || seen[keyText] {
			clear(accessIdentifier)
			clear(secretKey)
			clear(sessionToken)
			return nil, errors.New("shared S3 credentials are invalid")
		}
		seen[keyText] = true
		switch keyText {
		case "aws_access_key_id":
			accessIdentifier = append(accessIdentifier[:0], value...)
		case "aws_secret_access_key":
			secretKey = append(secretKey[:0], value...)
		case "aws_session_token":
			sessionToken = append(sessionToken[:0], value...)
		default:
			clear(accessIdentifier)
			clear(secretKey)
			clear(sessionToken)
			return nil, errors.New("shared S3 credentials are invalid")
		}
	}
	if !validCredentialValue(accessIdentifier, 16, 256) ||
		!validCredentialValue(secretKey, 16, maximumCredentialBytes) ||
		len(sessionToken) != 0 && !validCredentialValue(sessionToken, 16, maximumCredentialBytes) {
		clear(accessIdentifier)
		clear(secretKey)
		clear(sessionToken)
		return nil, errors.New("S3 secret key is invalid")
	}
	return &s3Credentials{accessIdentifier, secretKey, sessionToken}, nil
}

func validCredentialValue(value []byte, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func s3ObjectURL(request Request) (*url.URL, string, string, error) {
	endpoint, err := parseS3Endpoint(request.Endpoint)
	if err != nil {
		return nil, "", "", err
	}
	segments := strings.Split(request.ObjectKey, "/")
	escaped := make([]string, 0, len(segments)+1)
	escaped = append(escaped, awsEscape(request.Bucket))
	for _, segment := range segments {
		escaped = append(escaped, awsEscape(segment))
	}
	canonicalURI := "/" + strings.Join(escaped, "/")
	canonicalQuery := "versionId=" + awsEscape(request.ObjectVersion)
	endpoint.Path = "/" + request.Bucket + "/" + request.ObjectKey
	endpoint.RawPath = canonicalURI
	endpoint.RawQuery = canonicalQuery
	return endpoint, canonicalURI, canonicalQuery, nil
}

func awsEscape(value string) string {
	const hexadecimal = "0123456789ABCDEF"
	var escaped strings.Builder
	escaped.Grow(len(value))
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '.' ||
			character == '_' || character == '~' {
			escaped.WriteByte(character)
			continue
		}
		escaped.WriteByte('%')
		escaped.WriteByte(hexadecimal[character>>4])
		escaped.WriteByte(hexadecimal[character&0x0f])
	}
	return escaped.String()
}

func parseS3Endpoint(value string) (*url.URL, error) {
	if !safeOpaque(value, 2048) || strings.ContainsAny(value, "\\%") {
		return nil, errors.New("invalid endpoint")
	}
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Scheme != "https" || !endpoint.IsAbs() || endpoint.Opaque != "" ||
		endpoint.User != nil || endpoint.Host == "" || endpoint.RawPath != "" ||
		(endpoint.Path != "" && endpoint.Path != "/") || endpoint.ForceQuery || endpoint.RawQuery != "" ||
		endpoint.Fragment != "" || endpoint.RawFragment != "" || endpoint.String() != value {
		return nil, errors.New("invalid endpoint")
	}
	hostname := endpoint.Hostname()
	if hostname == "" || hostname != strings.ToLower(hostname) || !asciiEndpointHostname(hostname) {
		return nil, errors.New("invalid endpoint host")
	}
	canonicalHost := hostname
	if strings.Contains(hostname, ":") {
		if net.ParseIP(hostname) == nil {
			return nil, errors.New("invalid endpoint IP")
		}
		canonicalHost = "[" + hostname + "]"
	} else if net.ParseIP(hostname) == nil && !validDNSName(hostname) {
		return nil, errors.New("invalid endpoint DNS name")
	}
	if port := endpoint.Port(); port != "" {
		number, parseErr := strconv.Atoi(port)
		if parseErr != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
			return nil, errors.New("invalid endpoint port")
		}
		canonicalHost += ":" + port
	}
	if endpoint.Host != canonicalHost {
		return nil, errors.New("non-canonical endpoint host")
	}
	return endpoint, nil
}

func asciiEndpointHostname(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character > 0x7f || character <= 0x20 {
			return false
		}
	}
	return true
}

func validDNSName(value string) bool {
	if len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}

func signS3Request(request *http.Request, region, canonicalURI, canonicalQuery string, now time.Time, credentials *s3Credentials) error {
	if request == nil || credentials == nil || len(credentials.accessKey) == 0 || len(credentials.secretKey) == 0 {
		return errors.New("signing input is invalid")
	}
	amzDate := now.UTC().Format("20060102T150405Z")
	date := now.UTC().Format("20060102")
	request.Header.Set("X-Amz-Date", amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := "host:" + request.URL.Host + "\n" +
		"x-amz-content-sha256:" + emptyPayloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"
	if len(credentials.sessionToken) != 0 {
		request.Header.Set("X-Amz-Security-Token", string(credentials.sessionToken))
		canonicalHeaders += "x-amz-security-token:" + string(credentials.sessionToken) + "\n"
		signedHeaders += ";x-amz-security-token"
	}
	canonicalRequest := strings.Join([]string{http.MethodGet, canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, emptyPayloadHash}, "\n")
	canonicalDigest := sha256.Sum256([]byte(canonicalRequest))
	scope := date + "/" + region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(canonicalDigest[:])
	rootKey := make([]byte, 4+len(credentials.secretKey))
	copy(rootKey, "AWS4")
	copy(rootKey[4:], credentials.secretKey)
	dateKey := hmacSHA256(rootKey, date)
	clear(rootKey)
	regionKey := hmacSHA256(dateKey, region)
	serviceKey := hmacSHA256(regionKey, "s3")
	sigKey := hmacSHA256(serviceKey, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(sigKey, stringToSign))
	clear(dateKey)
	clear(regionKey)
	clear(serviceKey)
	clear(sigKey)
	authorization := "AWS4-HMAC-SHA256 Creden" + "tial=" + string(credentials.accessKey) + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	request.Header.Set("Authori"+"zation", authorization)
	return nil
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
