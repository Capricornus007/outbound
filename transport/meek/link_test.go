package meek

import (
	"context"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type nilDialer struct{}

func (nilDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, context.Canceled
}

func TestNewMeekLinkCreator(t *testing.T) {
	const link = "meek://front.example:443?url=https://cdn.example/edge&host=front.example&sni=front.example#my-node"
	d, p, err := NewMeek(&dialer.ExtraOption{}, nilDialer{}, link)
	if err != nil {
		t.Fatalf("NewMeek: %v", err)
	}
	if _, ok := d.(*Dialer); !ok {
		t.Fatalf("NewMeek returned %T, want *meek.Dialer", d)
	}
	if p.Protocol != "meek" {
		t.Errorf("Protocol = %q, want %q", p.Protocol, "meek")
	}
	if p.Address != "front.example:443" {
		t.Errorf("Address = %q, want %q", p.Address, "front.example:443")
	}
	if p.Name != "my-node" {
		t.Errorf("Name = %q, want %q", p.Name, "my-node")
	}
	if p.Link != link {
		t.Errorf("Link = %q, want the original link", p.Link)
	}
}

// The front is where every byte goes, so a non-https url= would send the
// meek body in cleartext; meek has no plaintext backdrop.
func TestNewMeekRejectsUnusableBackdrop(t *testing.T) {
	for _, tc := range []struct{ name, link, want string }{
		{"missing url", "meek://front.example:443", "url is empty"},
		{"http backdrop", "meek://front.example:443?url=http://cdn.example/edge", "unimplemented backdrop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := NewMeek(&dialer.ExtraOption{}, nilDialer{}, tc.link)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewMeek(%q) = %v, want error containing %q", tc.link, err, tc.want)
			}
		})
	}
}

func TestNewMekyaCarriesKcpOptions(t *testing.T) {
	const link = "mekya://front.example:443?url=https://cdn.example/edge&seed=s33d&mtu=1400&tti=30&congestion=true#kcp-over-meek"
	d, p, err := NewMekya(&dialer.ExtraOption{}, nilDialer{}, link)
	if err != nil {
		t.Fatalf("NewMekya: %v", err)
	}
	md, ok := d.(*MekyaDialer)
	if !ok {
		t.Fatalf("NewMekya returned %T, want *meek.MekyaDialer", d)
	}
	if p.Protocol != "mekya" {
		t.Errorf("Protocol = %q, want %q", p.Protocol, "mekya")
	}
	if p.Name != "kcp-over-meek" {
		t.Errorf("Name = %q, want %q", p.Name, "kcp-over-meek")
	}
	if md.kcpConfig.Seed != "s33d" || md.kcpConfig.MTU != 1400 || md.kcpConfig.TTI != 30 || !md.kcpConfig.Congestion {
		t.Errorf("kcpConfig = %+v, want seed s33d / mtu 1400 / tti 30 / congestion true", *md.kcpConfig)
	}
	if md.mekyaConfig == nil || *md.mekyaConfig != *DefaultMekyaConfig() {
		t.Errorf("mekyaConfig = %+v, want the defaults", md.mekyaConfig)
	}
}

func TestNewMekyaRejectsBadKcpOptions(t *testing.T) {
	_, _, err := NewMekya(&dialer.ExtraOption{}, nilDialer{}, "mekya://front.example:443?url=https://cdn.example/edge&tti=2000")
	if err == nil || !strings.Contains(err.Error(), "tti") {
		t.Fatalf("NewMekya with tti=2000 = %v, want it rejected", err)
	}
}

// The meek layer owns TLS, so it is the one place a node-level
// allow_insecure has to land when the link is used as a top-level scheme.
func TestNewMeekAllowInsecureSources(t *testing.T) {
	for _, tc := range []struct {
		name   string
		link   string
		option *dialer.ExtraOption
		want   bool
	}{
		{"neither", "meek://h:443?url=https://f/e", &dialer.ExtraOption{}, false},
		{"link only", "meek://h:443?url=https://f/e&allowInsecure=true", &dialer.ExtraOption{}, true},
		{"skipVerify spelling", "meek://h:443?url=https://f/e&skipVerify=1", &dialer.ExtraOption{}, true},
		{"global only", "meek://h:443?url=https://f/e", &dialer.ExtraOption{AllowInsecure: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, err := NewMeek(tc.option, nilDialer{}, tc.link)
			if err != nil {
				t.Fatalf("NewMeek: %v", err)
			}
			got := d.(*Dialer)
			if got.skipVerify != tc.want {
				t.Errorf("skipVerify = %v, want %v", got.skipVerify, tc.want)
			}
			if got.tlsConfig.InsecureSkipVerify != tc.want {
				t.Errorf("tlsConfig.InsecureSkipVerify = %v, want %v", got.tlsConfig.InsecureSkipVerify, tc.want)
			}
		})
	}
}
