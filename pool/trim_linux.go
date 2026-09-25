//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package pool

import (
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// DefaultTrimThreshold is the consecutive idle rounds required before reclaiming physical pages.
const DefaultTrimThreshold = 3

// ReleasePhysicalPages aligns the byte slice to operating system page boundaries
// and advises the kernel with MADV_DONTNEED. The underlying physical frames are immediately
// surrendered back to the operating system, reducing the resident set size (RSS),
// while preserving the virtual address range.
func ReleasePhysicalPages(b []byte) (int, bool) {
	if len(b) == 0 {
		return 0, false
	}
	pageSize := uintptr(os.Getpagesize())
	ptr := uintptr(unsafe.Pointer(&b[0]))

	start := (ptr + pageSize - 1) &^ (pageSize - 1)
	end := (ptr + uintptr(len(b))) &^ (pageSize - 1)

	if end <= start {
		return 0, false
	}

	length := end - start
	slice := unsafe.Slice((*byte)(unsafe.Pointer(start)), length)
	err := unix.Madvise(slice, unix.MADV_DONTNEED)
	if err != nil {
		return 0, false
	}
	return int(length), true
}

// JumboBufferArena provides a pre-allocated mmap arena for large network buffers
// (such as Jumbo frames and GSO aggregation buffers), with automatic idle compaction
// and physical page reclamation.
type JumboBufferArena struct {
	mu            sync.Mutex
	data          []byte
	bufferSize    int
	totalBuffers  int
	freeIndices   []int
	inUse         int
	idleRounds    int
	isDecommitted bool
}

// NewJumboBufferArena creates a contiguous mmap arena for count buffers of size bufferSize.
func NewJumboBufferArena(count, bufferSize int) (*JumboBufferArena, error) {
	if count <= 0 || bufferSize <= 0 {
		panic("invalid count or bufferSize")
	}

	pageSize := os.Getpagesize()
	totalBytes := count * bufferSize
	totalBytes = (totalBytes + pageSize - 1) &^ (pageSize - 1)

	data, err := unix.Mmap(
		-1,
		0,
		totalBytes,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANON|unix.MAP_PRIVATE,
	)
	if err != nil {
		return nil, err
	}

	freeIndices := make([]int, count)
	for i := 0; i < count; i++ {
		freeIndices[i] = i
	}

	return &JumboBufferArena{
		data:         data,
		bufferSize:   bufferSize,
		totalBuffers: count,
		freeIndices:  freeIndices,
	}, nil
}

// Get borrows a buffer from the arena.
func (a *JumboBufferArena) Get() ([]byte, int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.freeIndices) == 0 {
		return nil, -1, false
	}

	idx := a.freeIndices[len(a.freeIndices)-1]
	a.freeIndices = a.freeIndices[:len(a.freeIndices)-1]
	a.inUse++
	a.idleRounds = 0
	a.isDecommitted = false

	offset := idx * a.bufferSize
	return a.data[offset : offset+a.bufferSize], idx, true
}

// Put returns a buffer back to the arena by index.
func (a *JumboBufferArena) Put(idx int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if idx < 0 || idx >= a.totalBuffers {
		return
	}

	a.freeIndices = append(a.freeIndices, idx)
	a.inUse--
	if a.inUse < 0 {
		a.inUse = 0
	}
}

// Trim yields physical memory pages back to the kernel if the arena remains
// completely idle for threshold rounds.
func (a *JumboBufferArena) Trim(threshold int) (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.inUse > 0 {
		a.idleRounds = 0
		return 0, false
	}

	a.idleRounds++
	if a.idleRounds >= threshold && !a.isDecommitted {
		freed, ok := ReleasePhysicalPages(a.data)
		if ok {
			a.isDecommitted = true
			return freed, true
		}
	}
	return 0, false
}

// Close unmaps the arena memory.
func (a *JumboBufferArena) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.data) > 0 {
		err := unix.Munmap(a.data)
		a.data = nil
		return err
	}
	return nil
}

// TrimProcessMemory performs a coordinated heap scavenge and OS memory handback.
func TrimProcessMemory() {
	runtime.GC()
	debug.FreeOSMemory()
}
