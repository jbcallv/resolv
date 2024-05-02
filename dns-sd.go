package resolv

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
	"github.com/syslab-wm/adt/set"
	"github.com/syslab-wm/functools"
	"github.com/syslab-wm/mu"
)

func (c *Client) lookupPTR(domain string) ([]*dns.PTR, error) {
	resp, err := c.Lookup(domain, dns.TypePTR)
	if err != nil {
		return nil, err
	}
	return CollectRRs[*dns.PTR](resp.Answer), nil
}

func (c *Client) lookupOnePTR(domain string) (*dns.PTR, error) {
	ptrs, err := c.lookupPTR(domain)
	if err != nil {
		return nil, err
	}
	return ptrs[0], nil
}

func (c *Client) getPTR(domain string) ([]string, error) {
	ptrs, err := c.lookupPTR(domain)
	if err != nil {
		return nil, err
	}
	domains := functools.Map[*dns.PTR, string](ptrs, func(ptr *dns.PTR) string {
		return ptr.Ptr
	})
	return domains, nil
}

func (c *Client) getOnePTR(domain string) (string, error) {
	ptr, err := c.lookupOnePTR(domain)
	if err != nil {
		return "", err
	}
	return ptr.Ptr, nil
}

func (c *Client) lookupTXT(domain string) ([]*dns.TXT, error) {
	resp, err := c.Lookup(domain, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	return CollectRRs[*dns.TXT](resp.Answer), nil
}

func (c *Client) lookupOneTXT(domain string) (*dns.TXT, error) {
	txts, err := c.lookupTXT(domain)
	if err != nil {
		return nil, err
	}
	return txts[0], nil
}

func (c *Client) getTXT(domain string) ([][]string, error) {
	txts, err := c.lookupTXT(domain)
	if err != nil {
		return nil, err
	}
	values := functools.Map[*dns.TXT, []string](txts, func(txt *dns.TXT) []string {
		return txt.Txt
	})
	return values, nil
}

func (c *Client) getOneTXT(domain string) ([]string, error) {
	txt, err := c.lookupOneTXT(domain)
	if err != nil {
		return nil, err
	}
	return txt.Txt, nil
}

func (c *Client) GetServiceBrowserDomains(domain string) ([]string, error) {
	fauxDomain := fmt.Sprintf("b._dns-sd._udp.%s", domain)
	return c.getPTR(fauxDomain)
}

func (c *Client) GetDefaultServiceBrowserDomain(domain string) (string, error) {
	fauxDomain := fmt.Sprintf("db._dns-sd._udp.%s", domain)
	return c.getOnePTR(fauxDomain)
}

func (c *Client) GetLegacyServiceBrowserDomains(domain string) ([]string, error) {
	fauxDomain := fmt.Sprintf("lb._dns-sd._udp.%s", domain)
	return c.getPTR(fauxDomain)
}

func (c *Client) GetAllServiceBrowserDomains(domain string) ([]string, error) {
	var errs []error
	domainSet := set.New[string]()

	names, err := c.GetServiceBrowserDomains(domain)
	if err != nil {
		//log.Printf("GetServiceBrowserDomains: err: %v", err)
		errs = append(errs, err)
	} else {
		//log.Printf("GetServiceBrowserDomains: names: %v", names)
		domainSet.Add(names...)
	}

	name, err := c.GetDefaultServiceBrowserDomain(domain)
	if err != nil {
		//log.Printf("GetDefaultServiceBrowserDomain: err: %v", err)
		errs = append(errs, err)
	} else {
		//log.Printf("GetDefaultServiceBrowserDomain: name: %s", name)
		domainSet.Add(name)
	}

	names, err = c.GetLegacyServiceBrowserDomains(domain)
	if err != nil {
		//log.Printf("GetLegacyServiceBrowserDomains: err: %v", err)
		errs = append(errs, err)
	} else {
		//log.Printf("GetLegacyServiceBrowserDomains: name: %s", name)
		domainSet.Add(names...)
	}

	if domainSet.Size() == 0 {
		if len(errs) == 0 {
			mu.BUG("got no answers, but got no errors")
		}
		return nil, errors.Join(errs...)
	}

	return domainSet.Items(), nil
}

func (c *Client) GetServices(domain string) ([]string, error) {
	fauxDomain := fmt.Sprintf("_services._dns-sd._udp.%s", domain)
	return c.getPTR(fauxDomain)
}

func (c *Client) GetServiceInstances(serviceDomain string) ([]string, error) {
	// serviceDomain has the form, e.g.,  _ssh._tcp.<domain>
	return c.getPTR(serviceDomain)
}

// aggregation of SRV, TXT, and A/AAAA records
type ServiceInstanceInfo struct {
	Name string

	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string

	Txt []string

	Addrs []string
}

func (info *ServiceInstanceInfo) String() string {
	return fmt.Sprintf("name: %s priority:%d weight:%d port:%d target:%s txt:%v addrs: %v",
		info.Name, info.Priority, info.Weight, info.Port, info.Target, info.Txt, info.Addrs)
}

func (c *Client) GetServiceInstanceInfo(domain string) (*ServiceInstanceInfo, error) {
	var addrs []string
	info := new(ServiceInstanceInfo)
	info.Name = domain

	// SRV must succeed
	resp, err := c.Lookup(domain, dns.TypeSRV)
	if err != nil {
		return nil, err
	}
	srvs := CollectRRs[*dns.SRV](resp.Answer)
	srv := srvs[0]

	info.Priority = srv.Priority
	info.Weight = srv.Weight
	info.Port = srv.Port
	info.Target = srv.Target

	// Check if Response includes A/AAAA in the Additional section
	as := CollectRRs[*dns.A](resp.Extra)
	for _, a := range as {
		if a.Hdr.Name != info.Target {
			continue
		}
		addr, ok := netip.AddrFromSlice(a.A)
		if !ok {
			continue
		}
		addrs = append(addrs, addr.String())
	}
	aaaas := CollectRRs[*dns.AAAA](resp.Extra)
	for _, aaaa := range aaaas {
		if aaaa.Hdr.Name != info.Target {
			continue
		}
		addr, ok := netip.AddrFromSlice(aaaa.AAAA)
		if !ok {
			continue
		}
		addrs = append(addrs, addr.String())
	}

	if len(addrs) > 0 {
		info.Addrs = addrs
	} else {
		// If no A/AAAA records in the Additional section, do A/AAAA queries

		// not an error if fails
		addrs, err := c.GetIPs(info.Target)
		if err == nil {
			info.Addrs = addrs
		}
	}

	// not an error if TXT doesn't succeed
	value, err := c.getOneTXT(domain)
	if err == nil {
		info.Txt = value
	}

	return info, nil
}

func ParseInstanceServiceDomain(name string) (instance string, service string, domain string) {
	protoIndex := -1
	labels := dns.SplitDomainName(name)

	// start with TLD label
	for i := len(labels) - 1; i >= 0; i-- {
		if labels[i] == "_tcp" || labels[i] == "_udp" || labels[i] == "_tls" {
			protoIndex = i
			break
		}
	}

	if protoIndex >= 1 {
		service = fmt.Sprintf("%s.%s", labels[protoIndex-1], labels[protoIndex])
		domain = dns.Fqdn(strings.Join(labels[protoIndex:], "."))
		serviceStart := strings.Index(name, service)
		instance = name[:serviceStart]
	} else {
		domain = name
	}

	return
}

/*
// TODO: move this to dns-sd.go
func ParseServiceName(domain string) string {
	protoIndex := -1
	labels := dns.SplitDomainName(domain)

	// start with TLD label
	for i := len(labels) - 1; i >= 0; i-- {
		if labels[i] == "_tcp" || labels[i] == "_udp" || labels[i] == "_tls" {
			protoIndex = i
			break
		}
	}

	if protoIndex >= 1 {
		return fmt.Sprintf("%s.%s", labels[protoIndex-1], labels[protoIndex])
	}

	return ""
}
*/
