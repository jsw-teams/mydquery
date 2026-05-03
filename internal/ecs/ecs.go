package ecs

import (
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

type Candidates struct {
	Visitor string
	Client  string
}

func Select(mode string, c Candidates) (string, string) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "visitor":
		if c.Visitor != "" {
			return c.Visitor, "visitor"
		}
	case "client":
		if c.Client != "" {
			return c.Client, "client"
		}
	case "none", "off", "":
		return "", "off"
	}
	return "", "missing"
}

func VisitorFromIP(ip string, v4Mask, v6Mask int) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "", false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Is4() {
		if v4Mask <= 0 || v4Mask > 32 {
			v4Mask = 24
		}
		p := netip.PrefixFrom(addr, v4Mask).Masked()
		return p.String(), true
	}
	if addr.Is6() {
		if v6Mask <= 0 || v6Mask > 128 {
			v6Mask = 48
		}
		p := netip.PrefixFrom(addr, v6Mask).Masked()
		return p.String(), true
	}
	return "", false
}

func NormalizeExplicit(value string, max4, max6 int) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}

	if strings.Contains(value, "/") {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return "", false
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits())
		}
		if p.Addr().Is4() {
			if max4 <= 0 || max4 > 32 {
				max4 = 24
			}
			if p.Bits() > max4 {
				p = netip.PrefixFrom(p.Addr(), max4)
			}
			p = p.Masked()
			return p.String(), true
		}
		if p.Addr().Is6() {
			if max6 <= 0 || max6 > 128 {
				max6 = 48
			}
			if p.Bits() > max6 {
				p = netip.PrefixFrom(p.Addr(), max6)
			}
			p = p.Masked()
			return p.String(), true
		}
		return "", false
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Is4() {
		if max4 <= 0 || max4 > 32 {
			max4 = 24
		}
		return netip.PrefixFrom(addr, max4).Masked().String(), true
	}
	if addr.Is6() {
		if max6 <= 0 || max6 > 128 {
			max6 = 48
		}
		return netip.PrefixFrom(addr, max6).Masked().String(), true
	}
	return "", false
}

func ExtractClientFromDNS(query *dns.Msg, max4, max6 int) (string, string) {
	opt := query.IsEdns0()
	if opt == nil {
		return "", "missing"
	}
	for _, item := range opt.Option {
		subnet, ok := item.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}
		addr, ok := ecsAddr(subnet)
		if !ok {
			return "", "invalid-dns-ecs"
		}
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
		bits := int(subnet.SourceNetmask)
		var normalized string
		switch {
		case addr.Is4():
			if max4 <= 0 || max4 > 32 {
				max4 = 24
			}
			if bits > max4 {
				bits = max4
			}
			normalized = netip.PrefixFrom(addr, bits).Masked().String()
		case addr.Is6():
			if max6 <= 0 || max6 > 128 {
				max6 = 48
			}
			if bits > max6 {
				bits = max6
			}
			normalized = netip.PrefixFrom(addr, bits).Masked().String()
		}
		if normalized != "" {
			return normalized, "dns-ecs"
		}
	}
	return "", "missing"
}

func ApplyToMessage(in *dns.Msg, ecsValue string) (*dns.Msg, error) {
	out := in.Copy()

	var opt *dns.OPT
	for _, rr := range out.Extra {
		if existing, ok := rr.(*dns.OPT); ok {
			opt = existing
			break
		}
	}
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(1232)
		out.Extra = append(out.Extra, opt)
	}

	filtered := make([]dns.EDNS0, 0, len(opt.Option))
	for _, item := range opt.Option {
		if _, ok := item.(*dns.EDNS0_SUBNET); ok {
			continue
		}
		filtered = append(filtered, item)
	}
	opt.Option = filtered

	if strings.TrimSpace(ecsValue) == "" {
		return out, nil
	}

	p, err := netip.ParsePrefix(strings.TrimSpace(ecsValue))
	if err != nil {
		return nil, err
	}
	addr := p.Addr()
	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	subnet := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, SourceNetmask: uint8(p.Bits()), SourceScope: 0}
	switch {
	case addr.Is4():
		subnet.Family = 1
		subnet.Address = addr.AsSlice()
	case addr.Is6():
		subnet.Family = 2
		subnet.Address = addr.AsSlice()
	default:
		return out, nil
	}
	opt.Option = append(opt.Option, subnet)
	return out, nil
}

func ecsAddr(subnet *dns.EDNS0_SUBNET) (netip.Addr, bool) {
	switch subnet.Family {
	case 1:
		if len(subnet.Address) < 4 {
			buf := make([]byte, 4)
			copy(buf, subnet.Address)
			subnet.Address = buf
		}
		addr, ok := netip.AddrFromSlice(subnet.Address[:4])
		return addr, ok
	case 2:
		if len(subnet.Address) < 16 {
			buf := make([]byte, 16)
			copy(buf, subnet.Address)
			subnet.Address = buf
		}
		addr, ok := netip.AddrFromSlice(subnet.Address[:16])
		return addr, ok
	default:
		return netip.Addr{}, false
	}
}
