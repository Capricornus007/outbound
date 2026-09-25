//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package pool

import (
	"errors"
	"runtime"
	"runtime/debug"
)

const DefaultTrimThreshold = 3

func ReleasePhysicalPages(b []byte) (int, bool) {
	return 0, false
}

type JumboBufferArena struct{}

func NewJumboBufferArena(count, bufferSize int) (*JumboBufferArena, error) {
	return nil, errors.New("jumbo buffer arena not supported on non-linux")
}

func (a *JumboBufferArena) Get() ([]byte, int, bool) {
	return nil, -1, false
}

func (a *JumboBufferArena) Put(idx int) {}

func (a *JumboBufferArena) Trim(threshold int) (int, bool) {
	return 0, false
}

func (a *JumboBufferArena) Close() error {
	return nil
}

func TrimProcessMemory() {
	runtime.GC()
	debug.FreeOSMemory()
}
