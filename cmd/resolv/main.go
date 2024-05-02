package main

import (
	"fmt"
	"strings"

	"github.com/syslab-wm/adt/set"
	"github.com/syslab-wm/functools"
	"github.com/syslab-wm/mu"
	"github.com/syslab-wm/netx"
	"github.com/syslab-wm/resolv"
)

/* meta queries */

func getIPs(c *resolv.Client, qname string) error {
	addrs, err := c.GetIPs(qname)
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		fmt.Println(addr)
	}

	return nil
}

func getNameservers(c *resolv.Client, qname string) error {
	nameservers, err := c.GetNameservers(qname)
	if err != nil {
		return err
	}

	for _, nameserver := range nameservers {
		strAddrs := functools.Map[string, string](nameserver.Addrs, func(addr string) string {
			return fmt.Sprintf("%v", addr)
		})
		fmt.Printf("%s: %s\n", nameserver.Name, strings.Join(strAddrs, " "))
	}

	return nil
}

func getServices(c *resolv.Client, qname string) error {
	browsers, _ := c.GetAllServiceBrowserDomains(qname)
	if browsers != nil {
		fmt.Printf("Service Browser Domains:\n")
		for _, browser := range browsers {
			fmt.Printf("\t%s\n", browser)
		}
	} else {
		// if we don't find any browsing domains, treat the original
		// domain as the browsing domain
		browsers = []string{qname}
	}

	serviceSet := set.New[string]()
	for _, browser := range browsers {
		services, err := c.GetServices(browser)
		if err != nil {
			continue
		}
		serviceSet.Add(services...)
	}

	services := serviceSet.Items()
	if len(services) != 0 {
		fmt.Printf("Services:\n")
		for _, service := range serviceSet.Items() {
			fmt.Printf("\t%s\n", service)
			instances, err := c.GetServiceInstances(service)
			if err != nil {
				continue
			}
			for _, instance := range instances {
				fmt.Printf("\t\t%s\n", instance)
				info, err := c.GetServiceInstanceInfo(instance)
				if err != nil {
					continue
				}
				fmt.Printf("\t\t\t%v\n", info)
			}
		}
	}

	return nil
}

/* normal query */

func doLookup(c *resolv.Client, qname string, qtype uint16) error {
	resp, err := c.Lookup(qname, qtype)
	if err != nil {
		return err
	}

	fmt.Printf("%v\n", resp)

	return nil
}

func main() {
	var err error

	opts := parseOptions()

	c := &resolv.Client{
		AD:           opts.adflag,
		CD:           opts.cdflag,
		ClientSubnet: opts.subnetPrefix,
		DO:           opts.dnssec,
		MaxCNAMEs:    opts.maxCNAMEs,
		NSID:         opts.nsid,
		RD:           opts.rdflag,
	}

	if opts.tcp {
		c.Transport = &resolv.Do53TCP{
			Server:   netx.TryJoinHostPort(opts.server, "53"),
			IPv4Only: opts.four,
			IPv6Only: opts.six,
			Timeout:  opts.timeout,
			KeepOpen: false,
		}
	} else if opts.tls {
		c.Transport = &resolv.DoT{
			Server:   netx.TryJoinHostPort(opts.server, resolv.DefaultDoTPort),
			IPv4Only: opts.four,
			IPv6Only: opts.six,
			Timeout:  opts.timeout,
			KeepOpen: false,
		}
	} else if opts.httpsURL != "" {
		c.Transport = &resolv.DoH{
			ServerURL: opts.httpsURL,
			Timeout:   opts.timeout,
			UseGET:    opts.httpsUseGET,
			KeepOpen:  false,
		}
	} else {
		c.Transport = &resolv.Do53UDP{
			Server:           netx.TryJoinHostPort(opts.server, "53"),
			IPv4Only:         opts.four,
			IPv6Only:         opts.six,
			Timeout:          opts.timeout,
			UDPBufSize:       opts.bufsize,
			IgnoreTruncation: opts.ignore,
		}
	}

	switch opts.qtypeStr {
	case "@IPS":
		err = getIPs(c, opts.qname)
	case "@NAMESERVERS":
		err = getNameservers(c, opts.qname)
	case "@SERVICES":
		err = getServices(c, opts.qname)
	default:
		err = doLookup(c, opts.qname, opts.qtype)
	}
	c.Close()

	if err != nil {
		mu.Fatalf("query failed: %v", err)
	}
}
