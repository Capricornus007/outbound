package dialer_test

import (
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/socks"
	_ "github.com/daeuniverse/outbound/transport/meek"
	_ "github.com/daeuniverse/outbound/transport/mkcp"
)

// mKCP and Mekya live in transport/* and are linked into consumers only
// because dialer/v2ray imports them for its transport= switch. Their schemes
// nevertheless have to resolve standalone, because subscriptions ship
// bare kcp://, meek:// and mekya:// links. This is that guarantee.
func TestRegistryResolvesKcpAndMeekSchemes(t *testing.T) {
	base, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	for _, tc := range []struct {
		link       string
		wantScheme string
		wantAddr   string
		wantName   string
	}{
		{"mkcp://127.0.0.1:4000?seed=s#mkcp-node", "mkcp", "127.0.0.1:4000", "mkcp-node"},
		{"kcp://127.0.0.1:4001?mtu=1400#kcp-alias", "mkcp", "127.0.0.1:4001", "kcp-alias"},
		{"meek://127.0.0.1:443?url=https%3A%2F%2Ffront.example%2Fedge#meek-node", "meek", "127.0.0.1:443", "meek-node"},
		{"mekya://127.0.0.1:443?url=https%3A%2F%2Ffront.example%2Fedge&seed=s#mekya-node", "mekya", "127.0.0.1:443", "mekya-node"},
	} {
		t.Run(tc.link, func(t *testing.T) {
			d, p, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, tc.link)
			if err != nil {
				t.Fatalf("NewNetproxyDialerFromLink(%q): %v", tc.link, err)
			}
			if d == nil {
				t.Fatal("nil dialer with no error")
			}
			if p.Protocol != tc.wantScheme {
				t.Errorf("Protocol = %q, want %q", p.Protocol, tc.wantScheme)
			}
			if p.Address != tc.wantAddr {
				t.Errorf("Address = %q, want %q", p.Address, tc.wantAddr)
			}
			if p.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", p.Name, tc.wantName)
			}
		})
	}
}

// A bad KCP parameter must fail at link-parse time, not on the first dial.
func TestRegistryRejectsBrokenKcpLinks(t *testing.T) {
	base, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	for _, tc := range []struct{ link, want string }{
		{"mkcp://127.0.0.1:4000?tti=2000", "tti"},
		{"mkcp://127.0.0.1:4000?mtu=100", "mtu"},
		{"mekya://127.0.0.1:443?seed=s", "url is empty"},
	} {
		_, _, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, tc.link)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("NewNetproxyDialerFromLink(%q) = %v, want error containing %q", tc.link, err, tc.want)
		}
	}
}

// Chains keep working: KCP as the innermost hop is how a subscription says
// "this node rides on mKCP", and the property must name both hops.
func TestRegistryResolvesKcpAsChainBase(t *testing.T) {
	base, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	_, p, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{},
		"socks5://127.0.0.1:1080->mkcp://127.0.0.1:4000")
	if err != nil {
		t.Fatalf("socks5 over mkcp chain: %v", err)
	}
	if p.Protocol != "socks5->mkcp" {
		t.Errorf("Protocol = %q, want %q", p.Protocol, "socks5->mkcp")
	}
	if p.Address != "127.0.0.1:1080->127.0.0.1:4000" {
		t.Errorf("Address = %q, want both hops", p.Address)
	}
}
