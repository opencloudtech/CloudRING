// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package etcdrecovery

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const maximumS3ObjectReadDuration = 5 * time.Minute

// S3ObjectReadRequest identifies the one immutable object whose selected
// inventory metadata must be proved before its content is consumed. The
// caller keeps the credentials and any raw object identity in its protected
// runtime boundary; this request contains only the exact read coordinates and
// the selected size and ETag binding.
type S3ObjectReadRequest struct {
	Endpoint             string    `json:"endpoint"`
	Region               string    `json:"region"`
	Bucket               string    `json:"bucket"`
	ObjectKey            string    `json:"objectKey"`
	ExpectedBytes        int64     `json:"expectedBytes"`
	ExpectedETag         string    `json:"expectedETag"`
	ExpectedLastModified time.Time `json:"expectedLastModified"`
}

// S3ObjectReadResult is source-safe read proof. The raw object key, ETag,
// version, credentials, and object contents are deliberately absent.
type S3ObjectReadResult struct {
	Bytes               int64  `json:"bytes"`
	ContentSHA256       string `json:"contentSha256"`
	ObjectVersionSHA256 string `json:"objectVersionSha256"`
}

// ReadS3Object performs an exact, bounded read of one immutable S3-compatible
// object. A signed HEAD first binds the selected size and ETag to a concrete
// non-null version. The subsequent GET is pinned to that version and guarded
// by If-Match. The object is streamed through SHA-256 and is never written to
// disk or retained in the returned result.
func ReadS3Object(
	ctx context.Context,
	request S3ObjectReadRequest,
	sharedCredentials []byte,
	now time.Time,
) (S3ObjectReadResult, error) {
	client := newS3Client()
	defer client.CloseIdleConnections()
	return readS3ObjectWithClient(ctx, request, sharedCredentials, now, client)
}

func readS3ObjectWithClient(
	ctx context.Context,
	request S3ObjectReadRequest,
	sharedCredentials []byte,
	now time.Time,
	client *http.Client,
) (S3ObjectReadResult, error) {
	if ctx == nil || client == nil || !validS3ObjectReadRequest(request) || now.IsZero() {
		return S3ObjectReadResult{}, errors.New("S3 object read input is invalid")
	}
	readContext, cancel := context.WithTimeout(ctx, maximumS3ObjectReadDuration)
	defer cancel()
	credentials, err := parseSharedS3Credentials(sharedCredentials)
	if err != nil {
		return S3ObjectReadResult{}, errors.New("S3 object read credentials are unavailable")
	}
	defer credentials.clear()

	headURL, canonicalURI, _, err := s3ObjectURL(Request{
		Endpoint:  request.Endpoint,
		Region:    request.Region,
		Bucket:    request.Bucket,
		ObjectKey: request.ObjectKey,
		// s3ObjectURL builds the exact object path from the request. The
		// HEAD is intentionally unversioned; its response selects the
		// immutable version that the GET then pins.
		ObjectVersion: "head",
	})
	if err != nil {
		return S3ObjectReadResult{}, errors.New("S3 object read URL is invalid")
	}
	headURL.RawQuery = ""
	headURL.ForceQuery = false
	headRequest, err := http.NewRequestWithContext(readContext, http.MethodHead, headURL.String(), nil)
	if err != nil {
		return S3ObjectReadResult{}, errors.New("create S3 object metadata request")
	}
	headRequest.Header.Set("Accept", "application/octet-stream")
	headRequest.Header.Set("If-Match", request.ExpectedETag)
	headRequest.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	if err := signS3Request(headRequest, request.Region, canonicalURI, "", now.UTC(), credentials); err != nil {
		return S3ObjectReadResult{}, errors.New("sign S3 object metadata request")
	}
	response, err := doS3ObjectReadRequest(client, headRequest)
	clearS3RequestSecrets(headRequest)
	if err != nil {
		return S3ObjectReadResult{}, errors.New("read S3 object metadata")
	}
	if response == nil || response.Body == nil {
		return S3ObjectReadResult{}, errors.New("S3 object metadata response is invalid")
	}
	defer response.Body.Close()
	version, versionHeaderOK := singleS3ResponseHeader(response.Header, "X-Amz-Version-Id")
	etag, etagHeaderOK := singleS3ResponseHeader(response.Header, "ETag")
	lastModified, lastModifiedHeaderOK := singleS3ResponseHeader(response.Header, "Last-Modified")
	if response.StatusCode != http.StatusOK || response.ContentLength != request.ExpectedBytes ||
		!etagHeaderOK || etag != request.ExpectedETag ||
		!lastModifiedHeaderOK || !validS3ObjectLastModified(lastModified, request.ExpectedLastModified) ||
		!versionHeaderOK || !validS3ObjectVersion(version) {
		return S3ObjectReadResult{}, errors.New("S3 object metadata identity is invalid")
	}

	objectRequest := Request{
		Endpoint:      request.Endpoint,
		Region:        request.Region,
		Bucket:        request.Bucket,
		ObjectKey:     request.ObjectKey,
		ObjectVersion: version,
	}
	objectURL, objectCanonicalURI, objectCanonicalQuery, err := s3ObjectURL(objectRequest)
	if err != nil {
		return S3ObjectReadResult{}, errors.New("S3 object read URL is invalid")
	}
	getRequest, err := http.NewRequestWithContext(readContext, http.MethodGet, objectURL.String(), nil)
	if err != nil {
		return S3ObjectReadResult{}, errors.New("create S3 object request")
	}
	getRequest.Header.Set("Accept", "application/octet-stream")
	getRequest.Header.Set("If-Match", request.ExpectedETag)
	getRequest.Header.Set("X-Amz-Content-Sha256", emptyPayloadHash)
	if err := signS3Request(getRequest, request.Region, objectCanonicalURI, objectCanonicalQuery, now.UTC(), credentials); err != nil {
		return S3ObjectReadResult{}, errors.New("sign S3 object request")
	}
	response, err = doS3ObjectReadRequest(client, getRequest)
	clearS3RequestSecrets(getRequest)
	if err != nil {
		return S3ObjectReadResult{}, errors.New("read S3 object")
	}
	if response == nil || response.Body == nil {
		return S3ObjectReadResult{}, errors.New("S3 object response is invalid")
	}
	defer response.Body.Close()
	getVersion, getVersionHeaderOK := singleS3ResponseHeader(response.Header, "X-Amz-Version-Id")
	getETag, getETagHeaderOK := singleS3ResponseHeader(response.Header, "ETag")
	getLastModified, getLastModifiedHeaderOK := singleS3ResponseHeader(response.Header, "Last-Modified")
	if response.StatusCode != http.StatusOK || response.ContentLength != request.ExpectedBytes ||
		!getETagHeaderOK || getETag != request.ExpectedETag ||
		!getLastModifiedHeaderOK || !validS3ObjectLastModified(getLastModified, request.ExpectedLastModified) ||
		!getVersionHeaderOK || getVersion != version {
		return S3ObjectReadResult{}, errors.New("S3 object response identity is invalid")
	}

	digest, bytesRead, err := hashReaderContext(readContext, &contextReader{
		ctx:    readContext,
		reader: io.LimitReader(response.Body, request.ExpectedBytes+1),
	})
	versionDigest := sha256Hex([]byte(version))
	version = ""
	if err != nil || bytesRead != request.ExpectedBytes || readContext.Err() != nil {
		return S3ObjectReadResult{}, errors.New("S3 object content is invalid")
	}
	return S3ObjectReadResult{
		Bytes:               bytesRead,
		ContentSHA256:       digest,
		ObjectVersionSHA256: versionDigest,
	}, nil
}

func validS3ObjectReadRequest(request S3ObjectReadRequest) bool {
	_, err := parseS3Endpoint(request.Endpoint)
	return err == nil && safeS3Region(request.Region) && safeS3Bucket(request.Bucket) &&
		validObjectKey(request.ObjectKey) && request.ExpectedBytes > 0 &&
		request.ExpectedBytes <= MaxArchiveBytes && validS3ETag(request.ExpectedETag) &&
		!request.ExpectedLastModified.IsZero()
}

func validS3ETag(value string) bool {
	return safeOpaque(value, 1024) && value != "*"
}

func validS3ObjectVersion(value string) bool {
	return safeOpaque(value, 512) && !strings.EqualFold(value, "null")
}

func validS3ObjectLastModified(value string, expected time.Time) bool {
	if value == "" || expected.IsZero() {
		return false
	}
	parsed, err := time.Parse(http.TimeFormat, value)
	return err == nil && parsed.Equal(expected.UTC().Truncate(time.Second))
}

func singleS3ResponseHeader(headers http.Header, name string) (string, bool) {
	values := headers.Values(name)
	if len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

func doS3ObjectReadRequest(client *http.Client, request *http.Request) (*http.Response, error) {
	if client == nil || request == nil {
		return nil, errors.New("S3 object request is invalid")
	}
	safeClient := *client
	safeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := safeClient.Do(request)
	if err != nil {
		return nil, errors.New("S3 object transport failed")
	}
	return response, nil
}

func clearS3RequestSecrets(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del("Authorization")
	request.Header.Del("X-Amz-Security-Token")
}
