package vision

import (
	"bytes"
	gotls "crypto/tls"
	"fmt"
	"net"
	"reflect"
	"sync"
	"unsafe"

	"github.com/daeuniverse/outbound/netproxy"
	outboundtls "github.com/daeuniverse/outbound/transport/tls"
	utls "github.com/refraction-networking/utls"
)

type visionTLSReadBuffers struct {
	input    *bytes.Reader
	rawInput *bytes.Buffer
	// rawInputSlot／rawInputPtr 留著給呼叫端每次重讀：Go 1.28 起 crypto/tls 的
	// rawInput 是「延後分配的 *bytes.Buffer」，建連線那一刻抓到 nil 並不代表
	// 之後都是 nil——只存一次就會把 Vision 的 rawInput 快速路徑靜默關掉。
	rawInputSlot unsafe.Pointer
	rawInputPtr  bool
}

type visionTLSBufferOffsets struct {
	input    uintptr
	rawInput uintptr
	// rawInputPtr：Go 1.28 起 crypto/tls 把 conn.rawInput 從 bytes.Buffer（值）
	// 改成 *bytes.Buffer（指標）。兩種都要吃得下——舊版是「槽位本身就是那個
	// Buffer」，新版是「槽位裡放一個指標」，取法不同，不能只認一種。
	rawInputPtr bool
}

var visionTLSBufferOffsetCache sync.Map

func visionIntrinsicConn(conn netproxy.Conn) (net.Conn, netproxy.Conn, reflect.Type, unsafe.Pointer, error) {
	if _, ok := conn.(netproxy.IntrinsicConnProvider); !ok {
		return nil, nil, nil, nil, fmt.Errorf("XTLS only supports TLS and REALITY directly for now: %T", conn)
	}
	// Unwrap intermediate wrappers (such as BufferedReaderConn and the TLS read
	// coalescer) until we reach the actual TLS/REALITY connection. Each wrapper
	// exposes IntrinsicConn() that returns its child; TLS types are the terminal
	// leaves and do not implement it. The walk is bounded so a misbehaving
	// wrapper cannot hang the dial path.
	ic := netproxy.UnwrapIntrinsicConn(conn)
	switch tlsConn := ic.(type) {
	case *gotls.Conn:
		return tlsConn.NetConn(), tlsConn, reflect.TypeOf(tlsConn).Elem(), unsafe.Pointer(tlsConn), nil
	case *utls.UConn:
		if tlsConn.Conn == nil {
			return nil, nil, nil, nil, fmt.Errorf("XTLS received nil embedded uTLS connection: %T", ic)
		}
		return tlsConn.NetConn(), tlsConn, reflect.TypeOf(tlsConn.Conn).Elem(), unsafe.Pointer(tlsConn.Conn), nil
	case *outboundtls.RealityUConn:
		if tlsConn.UConn == nil || tlsConn.Conn == nil {
			return nil, nil, nil, nil, fmt.Errorf("XTLS received nil embedded REALITY connection: %T", ic)
		}
		return tlsConn.NetConn(), tlsConn.UConn, reflect.TypeOf(tlsConn.Conn).Elem(), unsafe.Pointer(tlsConn.Conn), nil
	default:
		return nil, nil, nil, nil, fmt.Errorf("XTLS only supports TLS and REALITY directly for now: %T", ic)
	}
}

func visionTLSBufferOffsetsFor(t reflect.Type) (visionTLSBufferOffsets, error) {
	if cached, ok := visionTLSBufferOffsetCache.Load(t); ok {
		return cached.(visionTLSBufferOffsets), nil
	}

	inputField, ok := t.FieldByName("input")
	if !ok {
		return visionTLSBufferOffsets{}, fmt.Errorf("XTLS cannot locate %s.input field", t)
	}
	if inputField.Type != reflect.TypeOf(bytes.Reader{}) {
		return visionTLSBufferOffsets{}, fmt.Errorf("XTLS unexpected %s.input type: %v", t, inputField.Type)
	}

	rawInputField, ok := t.FieldByName("rawInput")
	if !ok {
		return visionTLSBufferOffsets{}, fmt.Errorf("XTLS cannot locate %s.rawInput field", t)
	}
	var rawInputPtr bool
	switch rawInputField.Type {
	case reflect.TypeOf(bytes.Buffer{}):
	case reflect.TypeOf((*bytes.Buffer)(nil)):
		rawInputPtr = true
	default:
		return visionTLSBufferOffsets{}, fmt.Errorf("XTLS unexpected %s.rawInput type: %v（只吃 bytes.Buffer 或 *bytes.Buffer）", t, rawInputField.Type)
	}

	offsets := visionTLSBufferOffsets{
		input:       inputField.Offset,
		rawInput:    rawInputField.Offset,
		rawInputPtr: rawInputPtr,
	}
	visionTLSBufferOffsetCache.Store(t, offsets)
	return offsets, nil
}

func visionTLSReadBuffersFor(t reflect.Type, p unsafe.Pointer) (visionTLSReadBuffers, error) {
	offsets, err := visionTLSBufferOffsetsFor(t)
	if err != nil {
		return visionTLSReadBuffers{}, err
	}
	slot := unsafe.Add(p, offsets.rawInput)
	rawInput := (*bytes.Buffer)(slot)
	if offsets.rawInputPtr {
		// 槽位裡放的是指標，要把那個指標值讀出來（多一層間接）；尚未分配時就是
		// nil，所以這個值不能只存一次，要用 currentRawInput() 每次重讀。
		rawInput = *(*(*bytes.Buffer))(slot)
	}
	return visionTLSReadBuffers{
		input:        (*bytes.Reader)(unsafe.Add(p, offsets.input)),
		rawInput:     rawInput,
		rawInputSlot: slot,
		rawInputPtr:  offsets.rawInputPtr,
	}, nil
}

// currentRawInput 回傳 tls 內部 rawInput 緩衝「現在」的位置；尚未分配（新版）
// 或舊版已讀乾就回 nil。呼叫端一律要經過這裡，不要拿建連線當時存的 rawInput。
func (b visionTLSReadBuffers) currentRawInput() *bytes.Buffer {
	if b.rawInputPtr {
		return *(*(*bytes.Buffer))(b.rawInputSlot)
	}
	return b.rawInput
}
