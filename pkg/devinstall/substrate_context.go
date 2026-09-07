// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var ErrCredentials = errors.New("development substrate credentials are invalid; require one explicit inline context")

// The credential document is deliberately smaller than a general kubeconfig:
// there is no exec, auth-provider, tokenFile, proxy, insecure TLS or ambient
// lookup. A caller must stream the selected context on standard input.
type kubeConfig struct {
	APIVersion     string   `yaml:"apiVersion"`
	Kind           string   `yaml:"kind"`
	CurrentContext string   `yaml:"current-context"`
	Preferences    struct{} `yaml:"preferences"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server string `yaml:"server"`
			CA     string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token       string `yaml:"token"`
			Certificate string `yaml:"client-certificate-data"`
			Key         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
	} `yaml:"contexts"`
}

// NewClient consumes credentials once. They are held in memory only and are
// never copied into the installation journal, command arguments or reports.
func NewClient(reader io.Reader, profile Profile) (*Client, error) {
	if reader == nil || Validate(profile, Development) != nil {
		return nil, ErrCredentials
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maximumProfileBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumProfileBytes {
		return nil, ErrCredentials
	}
	defer clear(payload)
	var node yaml.Node
	if yaml.Unmarshal(payload, &node) != nil || !plainYAML(&node, 0) {
		return nil, ErrCredentials
	}
	var config kubeConfig
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	decoder.KnownFields(true)
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF || config.APIVersion != "v1" || config.Kind != "Config" ||
		len(config.Clusters) != 1 || len(config.Users) != 1 || len(config.Contexts) != 1 {
		return nil, ErrCredentials
	}
	cluster, user, selected := config.Clusters[0], config.Users[0], config.Contexts[0]
	if config.CurrentContext == "" || selected.Name != config.CurrentContext || cluster.Name == "" || user.Name == "" ||
		selected.Context.Cluster != cluster.Name || selected.Context.User != user.Name ||
		selected.Context.Namespace != "" && selected.Context.Namespace != profile.Target.Namespace ||
		strings.TrimSuffix(cluster.Cluster.Server, "/") != strings.TrimSuffix(profile.Target.APIServer, "/") {
		return nil, ErrCredentials
	}
	ca, err := base64.StdEncoding.Strict().DecodeString(cluster.Cluster.CA)
	if err != nil || len(ca) == 0 {
		return nil, ErrCredentials
	}
	defer clear(ca)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, ErrCredentials
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	bearer := user.User.Token
	if bearer != "" {
		if len(bearer) < 16 || len(bearer) > 32768 || strings.ContainsAny(bearer, " \t\r\n") || user.User.Certificate != "" || user.User.Key != "" {
			return nil, ErrCredentials
		}
	} else {
		certificate, err := base64.StdEncoding.Strict().DecodeString(user.User.Certificate)
		if err != nil {
			return nil, ErrCredentials
		}
		defer clear(certificate)
		key, err := base64.StdEncoding.Strict().DecodeString(user.User.Key)
		if err != nil {
			return nil, ErrCredentials
		}
		defer clear(key)
		pair, err := tls.X509KeyPair(certificate, key)
		if err != nil || len(pair.Certificate) == 0 {
			return nil, ErrCredentials
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
			return nil, ErrCredentials
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns: 8, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10, ForceAttemptHTTP2: true}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{profile: profile, http: client, transport: transport, bearer: bearer}, nil
}

func plainYAML(node *yaml.Node, depth int) bool {
	if node == nil || depth > 12 || node.Kind == yaml.AliasNode || node.Anchor != "" {
		return false
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[key.Value] || key.Value == "<<" {
				return false
			}
			seen[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if !plainYAML(child, depth+1) {
			return false
		}
	}
	return true
}
