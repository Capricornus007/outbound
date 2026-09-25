//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package pool

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPool_ReleasePhysicalPages(t *testing.T) {
	pageSize := os.Getpagesize()
	mem := make([]byte, pageSize*2)

	for i := range mem {
		mem[i] = 0x7a
	}

	freed, ok := ReleasePhysicalPages(mem)
	require.True(t, ok)
	require.Equal(t, len(mem), freed)

	// Memory is zeroed on demand upon read after MADV_DONTNEED
	require.Equal(t, byte(0), mem[0])

	// Re-dirtying succeeds
	mem[0] = 0x99
	require.Equal(t, byte(0x99), mem[0])
}

func TestPool_JumboBufferArena(t *testing.T) {
	bufferSize := 8192
	count := 8

	arena, err := NewJumboBufferArena(count, bufferSize)
	require.NoError(t, err)
	defer func() {
		_ = arena.Close()
	}()

	buf1, idx1, ok := arena.Get()
	require.True(t, ok)
	require.Equal(t, bufferSize, len(buf1))

	// In-use arena should not trim
	freed, trimmed := arena.Trim(1)
	require.False(t, trimmed)
	require.Equal(t, 0, freed)

	arena.Put(idx1)

	// Trim after idle rounds
	for i := 0; i < DefaultTrimThreshold-1; i++ {
		_, trimmed = arena.Trim(DefaultTrimThreshold)
		require.False(t, trimmed)
	}

	freed, trimmed = arena.Trim(DefaultTrimThreshold)
	require.True(t, trimmed)
	require.Positive(t, freed)
}
