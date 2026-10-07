// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Yuri Trukhin.

package kubeadm

import (
	"net/netip"
	"sort"
	"strings"
)

// HasIPv4AndIPv6CIDRs reports whether values contain valid CIDRs from both
// address families.
func HasIPv4AndIPv6CIDRs(values []string) bool {
	var hasIPv4 bool
	var hasIPv6 bool
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		if prefix.Addr().Is4() {
			hasIPv4 = true
		}
		if prefix.Addr().Is6() {
			hasIPv6 = true
		}
	}
	return hasIPv4 && hasIPv6
}

// HasIPv4AndIPv6Addresses reports whether the two inputs are respectively a
// valid IPv4 address and a valid IPv6 address.
func HasIPv4AndIPv6Addresses(ipv4, ipv6 string) bool {
	v4, err := netip.ParseAddr(strings.TrimSpace(ipv4))
	if err != nil || !v4.Is4() {
		return false
	}
	v6, err := netip.ParseAddr(strings.TrimSpace(ipv6))
	return err == nil && v6.Is6()
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func trimmedCopy(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
