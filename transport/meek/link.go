package meek

import (
	"fmt"
	"net/url"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/transport/mkcp"
)

func init() {
	dialer.FromLinkRegister("meek", NewMeek)
	dialer.FromLinkRegister("mekya", NewMekya)
}

// NewMeek is the bare meek:// link creator:
//
//	meek://host:port?url=https://front/endpoint&alpn=h2&sni=front&allowInsecure=true
//
// Only url= is required. Every byte goes to that front, so host:port is node
// identity (property, sticky-IP caching) rather than a dial target.
func NewMeek(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	d, p, err := parseMeekLink(link, nextDialer, option, "meek")
	if err != nil {
		return nil, nil, err
	}
	return d, p, nil
}

// NewMekya is mekya://<meek options>&<kcp options>: mKCP carried over the meek
// HTTP packet channel. KCP parameters share mkcp's query keys (seed, mtu, tti,
// uplink, downlink, congestion, readBuffer, writeBuffer).
func NewMekya(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	d, p, err := parseMeekLink(link, nextDialer, option, "mekya")
	if err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("NewMekya: %w", err)
	}
	kcpConfig, err := mkcp.ConfigFromQuery(u.Query())
	if err != nil {
		return nil, nil, fmt.Errorf("NewMekya: %w", err)
	}
	return NewMekyaDialer(d, kcpConfig), p, nil
}

func parseMeekLink(link string, nextDialer netproxy.Dialer, option *dialer.ExtraOption, protocol string) (*Dialer, *dialer.Property, error) {
	// NewDialer parses the link itself, so this second parse only fills in the
	// property; a link that fails here has already failed there.
	d, err := newDialerForLink(link, nextDialer, option)
	if err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("meek: %w", err)
	}
	return d, &dialer.Property{
		Name:     u.Fragment,
		Address:  u.Host,
		Protocol: protocol,
		Link:     link,
	}, nil
}

// newDialerForLink applies the global allow-insecure option on top of the
// link's own flag. Transport-level creators never look at ExtraOption (the
// protocol layer merges it into the query for them), but a scheme registered
// here can also be a top-level link, and then this is the only place where
// both sources meet.
func newDialerForLink(link string, nextDialer netproxy.Dialer, option *dialer.ExtraOption) (*Dialer, error) {
	d, err := NewDialer(link, nextDialer)
	if err != nil {
		return nil, err
	}
	if option != nil && option.AllowInsecure && !d.skipVerify {
		d.skipVerify = true
		d.tlsConfig.InsecureSkipVerify = true
	}
	return d, nil
}
