package mkcp

import "github.com/daeuniverse/outbound/dialer"

func init() {
	dialer.FromLinkRegister("mkcp", NewMkcp)
	dialer.FromLinkRegister("kcp", NewMkcp)
}
