package resolv

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/syslab-wm/functools"
	"github.com/syslab-wm/mu"
)

func (c *Client) GetIP4s(domain string) ([]string, error) {
	var addrs []string

	resp, err := c.Lookup(domain, dns.TypeA)
	if err != nil {
		return nil, err
	}

	as := CollectRRs[*dns.A](resp.Answer)
	for _, a := range as {
		addr, ok := netip.AddrFromSlice(a.A)
		if !ok {
			continue
		}
		addrs = append(addrs, addr.String())
	}

	if len(addrs) == 0 {
		return nil, ErrBadData
	}

	return addrs, nil
}

func (c *Client) GetIP6s(domain string) ([]string, error) {
	var addrs []string

	resp, err := c.Lookup(domain, dns.TypeAAAA)
	if err != nil {
		return nil, err
	}

	aaaas := CollectRRs[*dns.AAAA](resp.Answer)
	for _, aaaa := range aaaas {
		addr, ok := netip.AddrFromSlice(aaaa.AAAA)
		if !ok {
			continue
		}
		addrs = append(addrs, addr.String())
	}

	if len(addrs) == 0 {
		return nil, ErrBadData
	}

	return addrs, nil
}

func (c *Client) GetIPs(name string) ([]string, error) {
	var addrs []string
	var errs []error

	a, err := c.GetIP4s(name)
	if err != nil {
		errs = append(errs, err)
	} else {
		addrs = append(addrs, a...)
	}

	a, err = c.GetIP6s(name)
	if err != nil {
		errs = append(errs, err)
	} else {
		addrs = append(addrs, a...)
	}

	if len(addrs) > 0 {
		return addrs, nil
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	mu.BUG("neither addresses nor errors")
	return nil, nil
}

type Nameserver struct {
	Name  string
	Addrs []string
}

func (ns *Nameserver) String() string {
	return fmt.Sprintf("name: %s, addrs: %v", ns.Name, ns.Addrs)
}

func (c *Client) lookupNS(domain string) ([]*dns.NS, *dns.Msg, error) {
	resp, err := c.Lookup(domain, dns.TypeNS)
	if err != nil {
		return nil, resp, err
	}
	return CollectRRs[*dns.NS](resp.Answer), resp, nil
}

func (c *Client) getNS(domain string) ([]string, error) {
	var servers []string

	nses, resp, err := c.lookupNS(domain)
	if err == nil {
		servers = functools.Map[*dns.NS, string](nses, func(ns *dns.NS) string {
			return ns.Ns
		})
		return servers, nil
	}

	// check if the query returned RCode success, but failed because there
	// simply wasn't an answer.  In such a case, see if the Authority section
	// has an SOA entry, and return the nameserver in that entry
	if err == ErrRcode {
		return nil, err
	}

	if resp == nil {
		mu.BUG("expected non-nil Response ")
	}

	soas := CollectRRs[*dns.SOA](resp.Ns)
	if len(soas) == 0 {
		return nil, err
	}

	servers = functools.Map[*dns.SOA, string](soas, func(soa *dns.SOA) string {
		return soa.Ns
	})

	return servers, nil
}

func (c *Client) GetNameservers(name string) ([]*Nameserver, error) {
	var addrErrs []error
	var results []*Nameserver

	servers, err := c.getNS(name)
	if err != nil {
		return nil, err
	}

	for _, server := range servers {
		addrs, err := c.GetIPs(server)
		if err != nil {
			addrErrs = append(addrErrs, err)
			continue
		}
		results = append(results, &Nameserver{Name: server, Addrs: addrs})
	}

	if len(results) > 0 {
		return results, nil
	}

	if len(addrErrs) > 0 {
		return nil, errors.Join(addrErrs...)
	}

	mu.BUG("neither addresses nor errors")
	return nil, nil
}

// SVCB records for a DNS service identified as dns1.example.com would be queried at _dns.dns1.example.com.

// https://www.rfc-editor.org/rfc/rfc9461.html
// https://www.rfc-editor.org/rfc/rfc9462.html
/*
func (c *Client) GetDoHPath(name string) (string, error) {
    s := new(dns.SVCB)
    s.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeSVCB, Class: dns.ClassINET}

    e := new(dns.SVCBAlpn)
    e.Alphn = []string{"h2", "h3"}

    p := new(nds.SVCBDoHPath)
}
*/
