package main

import (
	"fmt"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/syslab-wm/resolv"
)

type SRVProbeResult struct {
	Services map[string][]*resolv.ServiceInstanceInfo
}

func NewSRVProbeResult() *SRVProbeResult {
	r := new(SRVProbeResult)
	r.Services = make(map[string][]*resolv.ServiceInstanceInfo)
	return r
}

func DoSRVProbe(id int, c *resolv.Client, domain string) *SRVProbeResult {
	var foundFlag bool
	r := NewSRVProbeResult()

	for _, service := range Services {
		name := fmt.Sprintf("%s.%s", service, domain)
		resp, err := c.Lookup(name, dns.TypeSRV)
		if err != nil {
			continue
		}
		srvs := resolv.CollectRRs[*dns.SRV](resp.Answer)
		as := resolv.CollectRRs[*dns.A](resp.Extra)
		aaaas := resolv.CollectRRs[*dns.AAAA](resp.Extra)
		for _, srv := range srvs {
			info := &resolv.ServiceInstanceInfo{
				Name:     name,
				Priority: srv.Priority,
				Weight:   srv.Weight,
				Port:     srv.Port,
				Target:   srv.Target,
			}

			// Check if Response includes A/AAAA in the Additional section
			var addrs []string
			for _, a := range as {
				if a.Hdr.Name != srv.Target {
					continue
				}
				addr, ok := netip.AddrFromSlice(a.A)
				if !ok {
					continue
				}
				addrs = append(addrs, addr.String())
			}
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

			r.Services[service] = append(r.Services[service], info)
			foundFlag = true
		}
	}

	if foundFlag {
		return r
	}
	return nil
}
