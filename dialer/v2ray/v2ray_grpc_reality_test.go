package v2ray_test

import (
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	_ "github.com/daeuniverse/outbound/protocol/vless"
	"github.com/daeuniverse/outbound/transport/grpc"
	"github.com/daeuniverse/outbound/transport/tls"
)

// unwrapOne peels a single transport layer off a dialer chain.
func unwrapOne(t *testing.T, d netproxy.Dialer) netproxy.Dialer {
	t.Helper()
	unwrapper, ok := d.(netproxy.DialerUnwrapper)
	if !ok {
		t.Fatalf("dialer %T does not expose its transport via UnwrapDialer", d)
	}
	return unwrapper.UnwrapDialer()
}

// TestVlessGRPCRealityDialerChain is a regression test for the outbound bug
// where "type=grpc" silently dropped every security=reality parameter
// (pbk/sid/fp/sni) and let gRPC negotiate its own standard TLS on top. The
// result was a REALITY + TLS double handshake that timed out on every node
// (0/36 in the field report).
//
// After the fix, a vless+reality+grpc link must build a chain of exactly:
//
//	vless protocol dialer -> grpc.Dialer{UpperEncrypted:true} -> *tls.Reality
//
// i.e. REALITY is applied to the raw stream *under* gRPC, and gRPC no longer
// wraps its own TLS (UpperEncrypted tells getGrpcClientConn to use
// insecure.NewCredentials, i.e. plaintext HTTP/2 over the REALITY stream).
func TestVlessGRPCRealityDialerChain(t *testing.T) {
	const link = "vless://a91a8755-0959-4298-af37-7151b1c41ccc@38.244.32.207:21921" +
		"?encryption=none&security=reality&sni=www.apple.com&fp=chrome" +
		"&pbk=yPkI93qDsGY5Knk4VxjtjjLHsmnBLPaf5aEBwcHg1SE&sid=41813ce90b43fe3f" +
		"&type=grpc&serviceName=grpc#vless-grpc-reality"

	got, _, err := v2ray.NewV2Ray(&dialer.ExtraOption{}, direct.SymmetricDirect, link)
	if err != nil {
		t.Fatalf("NewV2Ray() error = %v", err)
	}

	// Layer 1: the vless protocol dialer must hand off to the gRPC transport.
	grpcDialer, ok := unwrapOne(t, got).(*grpc.Dialer)
	if !ok {
		t.Fatalf("transport under vless = %T, want *grpc.Dialer", unwrapOne(t, got))
	}

	if !grpcDialer.UpperEncrypted {
		t.Fatal("grpc.Dialer.UpperEncrypted = false, want true for security=reality " +
			"(a false value here reintroduces the REALITY + TLS double handshake)")
	}
	if grpcDialer.ServiceName != "grpc" {
		t.Fatalf("grpc.Dialer.ServiceName = %q, want %q", grpcDialer.ServiceName, "grpc")
	}
	// SNI must be forwarded so the gRPC layer and the REALITY ClientHello agree.
	if grpcDialer.ServerName != "www.apple.com" {
		t.Fatalf("grpc.Dialer.ServerName = %q, want %q", grpcDialer.ServerName, "www.apple.com")
	}

	// Layer 2: gRPC's next dialer must be the REALITY wrapper, not the bare
	// direct dialer — this is the proof the reality parameters were not dropped.
	if _, ok := unwrapOne(t, grpcDialer).(*tls.Reality); !ok {
		t.Fatalf("transport under grpc = %T, want *tls.Reality", unwrapOne(t, grpcDialer))
	}
}

// TestVlessGRPCPlaintextKeepsLegacyChain guards the backward-compatibility
// half of the fix: without security=reality the grpc branch must behave
// exactly as before (no REALITY layer, UpperEncrypted false so gRPC still does
// its own standard TLS for a plain grpc/wss node).
func TestVlessGRPCPlaintextKeepsLegacyChain(t *testing.T) {
	const link = "vless://a91a8755-0959-4298-af37-7151b1c41ccc@38.244.32.207:21921" +
		"?encryption=none&security=none&type=grpc&serviceName=grpc#vless-grpc-plain"

	got, _, err := v2ray.NewV2Ray(&dialer.ExtraOption{}, direct.SymmetricDirect, link)
	if err != nil {
		t.Fatalf("NewV2Ray() error = %v", err)
	}

	grpcDialer, ok := unwrapOne(t, got).(*grpc.Dialer)
	if !ok {
		t.Fatalf("transport under vless = %T, want *grpc.Dialer", unwrapOne(t, got))
	}
	if grpcDialer.UpperEncrypted {
		t.Fatal("grpc.Dialer.UpperEncrypted = true for a non-reality node, want false")
	}
	if _, ok := unwrapOne(t, grpcDialer).(*tls.Reality); ok {
		t.Fatal("non-reality grpc node must not carry a *tls.Reality layer")
	}
}
