package main

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

func rrToString(rr dnsmessage.Resource) string {
	// Generic rendering by body type
	name := rr.Header.Name.String()
	typ := typeToString(rr.Header.Type)
	switch b := rr.Body.(type) {
	case *dnsmessage.AResource:
		return fmt.Sprintf("%s %s %d.%d.%d.%d", name, typ, b.A[0], b.A[1], b.A[2], b.A[3])
	case *dnsmessage.AAAAResource:
		// IPv6 as hex groups
		parts := make([]string, 8)
		for i := 0; i < 8; i++ {
			parts[i] = fmt.Sprintf("%x", uint16(b.AAAA[i*2])<<8|uint16(b.AAAA[i*2+1]))
		}
		return fmt.Sprintf("%s %s %s", name, typ, strings.Join(parts, ":"))
	case *dnsmessage.CNAMEResource:
		return fmt.Sprintf("%s %s %s", name, typ, b.CNAME.String())
	case *dnsmessage.TXTResource:
		return fmt.Sprintf("%s %s %q", name, typ, strings.Join(b.TXT, " "))
	case *dnsmessage.NSResource:
		return fmt.Sprintf("%s %s %s", name, typ, b.NS.String())
	case *dnsmessage.MXResource:
		return fmt.Sprintf("%s %s %d %s", name, typ, b.Pref, b.MX.String())
	case *dnsmessage.SRVResource:
		return fmt.Sprintf("%s %s %d %d %d %s", name, typ, b.Priority, b.Weight, b.Port, b.Target.String())
	default:
		return fmt.Sprintf("%s %s <opaque>", name, typ)
	}
}

func typeToString(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeSRV:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE%d", uint16(t))
	}
}

func rcodeToString(rc dnsmessage.RCode) string {
	switch rc {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", int(rc))
	}
}

func clientIPFromAddr(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.TCPAddr:
		return a.IP.String()
	default:
		// Fallback parse
		host, _, err := net.SplitHostPort(a.String())
		if err != nil {
			return a.String()
		}
		return host
	}
}
