//go:build linux || android || freebsd || openbsd

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package netproxy

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

var fwmarkIoctl int

func init() {
	switch runtime.GOOS {
	case "linux", "android":
		fwmarkIoctl = 36 /* unix.SO_MARK */
	case "freebsd":
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	case "openbsd":
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

// SoMarkControl is replacable. Replacibility is useful for Android.
var SoMarkControl = func(c syscall.RawConn, mark int) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, mark)
		if err != nil {
			sockOptErr = fmt.Errorf("error setting SO_MARK socket option: %w", err)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}

// SoMark is replacable. Replacibility is useful for Android.
var SoMark = func(fd int, mark int) error {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, fwmarkIoctl, mark); err != nil {
		return err
	}
	return nil
}

const (
	// SafeTCPMaxSeg defines a conservative TCP MSS (1380 bytes) to prevent
	// packet drops caused by PMTU black holes when packets are encapsulated
	// inside proxy or tunnel protocols (WireGuard, Shadowsocks, Trojan, TLS).
	SafeTCPMaxSeg = 1380
	// tcpFastOpenConnect is TCP_FASTOPEN_CONNECT on Linux (sockopt 30)
	tcpFastOpenConnect = 30
)

func isLoopbackTarget(address string) bool {
	if address == "" {
		return false
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if host == "localhost" {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsLoopback()
	}
	return false
}

// TCPDialControl applies performance and MTU safety socket options before connect:
// 1. fwmark if mark != 0
// 2. TCP_NODELAY = 1
// 3. TCP_MAXSEG = 1380 (MSS clamping for non-loopback WAN/proxy traffic)
// 4. TCP_FASTOPEN_CONNECT = 1 (best effort on Linux 4.11+)
var TCPDialControl = func(c syscall.RawConn, mark int, address ...string) error {
	var sockOptErr error
	isLoopback := len(address) > 0 && isLoopbackTarget(address[0])
	controlErr := c.Control(func(fd uintptr) {
		intFd := int(fd)
		if mark != 0 {
			if err := unix.SetsockoptInt(intFd, unix.SOL_SOCKET, fwmarkIoctl, mark); err != nil {
				sockOptErr = fmt.Errorf("error setting SO_MARK socket option: %w", err)
				return
			}
		}
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			_ = unix.SetsockoptInt(intFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
			if !isLoopback {
				_ = unix.SetsockoptInt(intFd, unix.IPPROTO_TCP, unix.TCP_MAXSEG, SafeTCPMaxSeg)
			}
			_ = unix.SetsockoptInt(intFd, unix.IPPROTO_TCP, tcpFastOpenConnect, 1)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}
