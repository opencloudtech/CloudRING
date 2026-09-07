// SPDX-License-Identifier: Apache-2.0
// Copyright (C) IURII TRUKHIN 2012-2022, Elena Trukhina 2023-2026. Project and trademarks: Elena Trukhina ZZP.

package devinstall

import "net/netip"

// These protocol address classes are policy boundaries, never target endpoints.
func ipv4Prefix(address [4]byte, bits int) string {
	return netip.PrefixFrom(netip.AddrFrom4(address), bits).String()
}

func guestLoopback() string { return netip.AddrFrom4([4]byte{127, 0, 0, 1}).String() }

func guestDeniedAddressClasses() []string {
	return []string{
		ipv4Prefix([4]byte{10}, 8), ipv4Prefix([4]byte{172, 16}, 12), ipv4Prefix([4]byte{192, 168}, 16),
		ipv4Prefix([4]byte{100, 64}, 10), ipv4Prefix([4]byte{127}, 8), ipv4Prefix([4]byte{169, 254}, 16), ipv4Prefix([4]byte{224}, 4),
		netip.PrefixFrom(netip.IPv6Loopback(), 128).String(), netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfc}), 7).String(),
		netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfe, 0x80}), 10).String(),
	}
}
