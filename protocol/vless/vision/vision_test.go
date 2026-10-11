package vision

import (
	gotls "crypto/tls"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	outboundtls "github.com/daeuniverse/outbound/transport/tls"
	utls "github.com/refraction-networking/utls"
)

type intrinsicConnWrapper struct {
	netproxy.Conn
	intrinsic netproxy.Conn
}

func (w *intrinsicConnWrapper) IntrinsicConn() netproxy.Conn {
	return w.intrinsic
}

// tlsBuffersResolved 判「NewConn 真的有拿到 crypto/tls 內部的兩個讀取緩衝」。
// 舊版 rawInput 是內嵌的 bytes.Buffer，兩個都必然非 nil；Go 1.28 起它是**延後分配**
// 的 *bytes.Buffer，還沒讀過就是 nil 屬正常態，所以指標形態改要求「槽位解析得出來」
// （rawInputSlot 非空）。斷言要認得這兩種形態，不然測試會把新版正當行為當成壞。
func tlsBuffersResolved(conn *Conn) bool {
	if conn.input == nil {
		return false
	}
	if conn.tlsBuffers.rawInputPtr {
		return conn.tlsBuffers.rawInputSlot != nil
	}
	return conn.tlsBuffers.currentRawInput() != nil
}


func TestNewConnAcceptsTLSConn(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	tlsConn := gotls.Client(client, &gotls.Config{InsecureSkipVerify: true})
	conn, err := NewConn(&intrinsicConnWrapper{Conn: tlsConn, intrinsic: tlsConn}, make([]byte, 16))
	if err != nil {
		t.Fatalf("NewConn returned error: %v", err)
	}
	if !tlsBuffersResolved(conn) {
		t.Fatal("expected internal TLS buffers to be resolved")
	}
}

func TestNewConnAcceptsUTLSConn(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	uConn := utls.UClient(client, &utls.Config{InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	conn, err := NewConn(&intrinsicConnWrapper{Conn: uConn, intrinsic: uConn}, make([]byte, 16))
	if err != nil {
		t.Fatalf("NewConn returned error: %v", err)
	}
	if !tlsBuffersResolved(conn) {
		t.Fatal("expected internal uTLS buffers to be resolved")
	}
}

func TestNewConnAcceptsRealityConn(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	uConn := utls.UClient(client, &utls.Config{InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	realityConn := &outboundtls.RealityUConn{UConn: uConn}
	conn, err := NewConn(&intrinsicConnWrapper{Conn: realityConn, intrinsic: realityConn}, make([]byte, 16))
	if err != nil {
		t.Fatalf("NewConn returned error: %v", err)
	}
	if !tlsBuffersResolved(conn) {
		t.Fatal("expected internal REALITY buffers to be resolved")
	}
}

func TestNewConnRejectsUnsupportedIntrinsicConn(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	if _, err := NewConn(client, make([]byte, 16)); err == nil {
		t.Fatal("expected error for connection without IntrinsicConn")
	}
}

// TestNewConnAcceptsBufferedReaderWrappedTLSConn is a regression test for the
// XTLS-only-supports-TLS-and-REALITY-directly-for-now error that appeared when
// protocol dialers started wrapping the underlying TLS connection with
// netproxy.BufferedReaderConn for syscall coalescing. Vision must still be
// able to reflect on the *tls.Conn underneath the bufio wrapper.
func TestNewConnAcceptsBufferedReaderWrappedTLSConn(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	tlsConn := gotls.Client(client, &gotls.Config{InsecureSkipVerify: true})
	wrapped := netproxy.ForceBufferedReaderConn(tlsConn, 0)
	conn, err := NewConn(wrapped, make([]byte, 16))
	if err != nil {
		t.Fatalf("NewConn returned error: %v", err)
	}
	if !tlsBuffersResolved(conn) {
		t.Fatal("expected internal TLS buffers to be resolved through the bufio wrapper")
	}
}

// TestNewConnAcceptsBufferedReaderWrappedRealityConn mirrors the TLS test
// above for REALITY connections, which is the configuration the original bug
// report surfaced on.
func TestNewConnAcceptsBufferedReaderWrappedRealityConn(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	uConn := utls.UClient(client, &utls.Config{InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	realityConn := &outboundtls.RealityUConn{UConn: uConn}
	wrapped := netproxy.ForceBufferedReaderConn(realityConn, 0)
	conn, err := NewConn(wrapped, make([]byte, 16))
	if err != nil {
		t.Fatalf("NewConn returned error: %v", err)
	}
	if !tlsBuffersResolved(conn) {
		t.Fatal("expected internal REALITY buffers to be resolved through the bufio wrapper")
	}
}
