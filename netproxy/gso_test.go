//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netproxy

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNetproxyUDPGSO_Cmsg(t *testing.T) {
	segmentSize := uint16(1400)
	cmsg := BuildUDPGSOControlMsg(segmentSize)
	require.NotEmpty(t, cmsg)

	parsed, err := unix.ParseSocketControlMessage(cmsg)
	require.NoError(t, err)
	require.Len(t, parsed, 1)

	hdr := parsed[0].Header
	require.Equal(t, int32(SolUDP), hdr.Level)
	require.Equal(t, int32(UDPSEGMENT), hdr.Type)
}

func TestNetproxyUDPGSO_ProbeAndLoopback(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer conn.Close()

	supported := ProbeUDPGSO(conn)
	t.Logf("ProbeUDPGSO supported: %v", supported)

	err = EnableUDPGRO(conn)
	t.Logf("EnableUDPGRO result: %v", err)

	ap := netip.MustParseAddrPort("127.0.0.1:53")
	sa := SockaddrFromAddrPort(ap)
	require.NotNil(t, sa)
	sa4, ok := sa.(*unix.SockaddrInet4)
	require.True(t, ok)
	require.Equal(t, 53, sa4.Port)
	require.Equal(t, [4]byte{127, 0, 0, 1}, sa4.Addr)
}
