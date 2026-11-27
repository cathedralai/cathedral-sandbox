package vmroot

import (
	"errors"
	"net/netip"
	"regexp"
)

// The link is the fw_cfg name opt/cathedral/link: "<host ip> <guest ip>", the kit's format
// (launch-guest.sh:87). It is not security relevant, because the host owns the network, but it is
// checked with the rules of guest-constants.sh sealed_link_check (without the room networks, which
// a VM does not have): IPv4, the first and second address of one private /30, host first.
var linkRe = regexp.MustCompile(`^([0-9.]{7,15}) ([0-9.]{7,15})$`)

// Link is a checked pair of addresses.
type Link struct{ Host, Guest netip.Addr }

// ParseLink checks raw (at most 64 bytes, no newline) and returns the pair.
func ParseLink(raw []byte) (Link, error) {
	if len(raw) == 0 || len(raw) > 64 {
		return Link{}, errors.New("vmroot: link size")
	}
	m := linkRe.FindSubmatch(raw)
	if m == nil {
		return Link{}, errors.New("vmroot: link is not '<host ip> <guest ip>'")
	}
	host, err1 := netip.ParseAddr(string(m[1]))
	guest, err2 := netip.ParseAddr(string(m[2]))
	if err1 != nil || err2 != nil || !host.Is4() || !guest.Is4() ||
		host.String() != string(m[1]) || guest.String() != string(m[2]) { // refuses leading zeros
		return Link{}, errors.New("vmroot: link addresses must be canonical IPv4")
	}
	h, g := host.As4(), guest.As4()
	hv := uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
	gv := uint32(g[0])<<24 | uint32(g[1])<<16 | uint32(g[2])<<8 | uint32(g[3])
	if hv%4 != 1 || gv != hv+1 {
		return Link{}, errors.New("vmroot: link must be the first and second address of one /30")
	}
	private := hv>>24 == 10 || hv>>20 == (172<<4|1) || hv>>16 == (192<<8|168)
	if !private {
		return Link{}, errors.New("vmroot: link must be in 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16")
	}
	return Link{Host: host, Guest: guest}, nil
}

// NetworkFile is /run/systemd/network/10-uplink.network. It matches any Ethernet link, since the
// VM has exactly one virtio NIC and the customer's OS names it. DNS is the host's default
// (vm_ctl.py VM_DNS) because the link carries no resolver.
func (l Link) NetworkFile() []byte {
	return []byte("[Match]\nType=ether\n\n[Network]\nAddress=" + l.Guest.String() + "/30\nGateway=" + l.Host.String() +
		"\nDNS=1.1.1.1\nDNS=8.8.8.8\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n")
}
