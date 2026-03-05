package hscontrol

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/query"
	"github.com/miekg/dns"
)

type StubResolver struct {
	timeout              time.Duration
	recursiveNameservers []string
}

func (s *StubResolver) CheckDNSPropagation(name, value string) error {
	// First, we need to know where the domain name points, i.e. If there are any CNAMEs
	query := makeDNSQuery(name, dns.TypeTXT, true)
	response, err := s.doDNSQuery(query)
	if err != nil {
		return fmt.Errorf("Failed to look up name %s: %w", name, err)
	}

	if response.Rcode == dns.RcodeSuccess || response.Rcode == dns.RcodeNameError {
		name = getFinalCNAMETarget(response, name)
	}
	authoritativeNss, err := s.findAuthoritativeNameservers(name)
	if err != nil {
		return err
	}

	/*
		found, err := checkNameserversPropagation(fqdn, value, authoritativeNss, true)
		if err != nil {
			return fmt.Errorf("authoritative nameservers: %w", err)
		}
	*/

	return nil
}

func (s *StubResolver) findAuthoritativeNameservers(name string) ([]string, error) {
	var ret []string

	var response *dns.Msg
	for _, offset := range dns.Split(name) {
		lookupName := name[offset:]
		query := makeDNSQuery(lookupName, dns.TypeSOA, true)
		var err error
		response, err = s.doDNSQuery(query)
		if err != nil {
			return nil, err
		}
		if response.Rcode == dns.RcodeSuccess {
			break
		}
	}

	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("Unable to determine authoritave zone name through SOA query")
	}

	var authZoneName string
	for _, ans := range response.Answer {
		if ans.Header().Rrtype == dns.TypeSOA {
			authZoneName = ans.Header().Name
			break
		}
	}

	if len(authZoneName) == 0 {
		return nil, fmt.Errorf("Unable to determine authoritative zone name")
	}

	query := makeDNSQuery(authZoneName, dns.TypeNS, true)
	response, err := s.doDNSQuery(query)
	if err != nil {
		return nil, err
	}

	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("Unable to determine authoritave zone nameservers")
	}

	var authNSNames []string
	for _, ans := range response.Answer {
		if ans.Header().Name == authZoneName {
			authNSNames = append(authNSNames, ans.String())
		}
	}

	for _, nsname := range authNSNames {
		// TODO: IPv6 / AAAA queries
		query = makeDNSQuery(nsname, dns.TypeA, true)
		response, err = s.doDNSQuery(query)
		// XXX: Perhaps we could do without *all* auth NS servers
		if err != nil {
			return nil, err
		}
		if response.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("Unable to get address for nameserver %s", nsname)
		}
		for _, ans := range response.Answer {
			if ans.Header().Name == nsname {
				ret = append(ret, ans.String())
			}
		}
	}
	return ret, nil
}

func waitForRecordAtAuth(authAddresses []string, qname string, qtype uint16, value string, queryTimeout, totalTimeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	for _, address := range authAddresses {
		query := makeDNSQuery(qname, qtype, false)
		response, err := doDNSQuery(query, address, queryTimeout)
		if err != nil {
			// TODO: retry
			return err
		}
		if response.Rcode != dns.RcodeSuccess {
			// TODO: retry
			continue
		}
		for _, ans := range response.Answer {
			if ans.Header().Name == qname && ans.Header().Rrtype == qtype && ans.String() == value {
				// we're good
				continue
			} else {
				// TODO: retry
				continue
			}
		}
	}

	return nil
}

func (s *StubResolver) doDNSQuery(query *dns.Msg) (*dns.Msg, error) {
	var err error
	var response *dns.Msg
	for _, nameserver := range s.recursiveNameservers {
		response, err = doDNSQuery(query, nameserver, s.timeout)
		if response.Rcode == dns.RcodeSuccess || response.Rcode == dns.RcodeNameError {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	return response, nil
}

func doDNSQuery(query *dns.Msg, nameserver string, timeout time.Duration) (*dns.Msg, error) {
	client := dns.Client{Net: "udp", Timeout: timeout}
	response, _, err := client.Exchange(query, nameserver)
	if response != nil && response.Truncated {
		client = dns.Client{Net: "tcp", Timeout: timeout}
		response, _, err = client.Exchange(query, nameserver)
	}

	if err != nil {
		return nil, err
	}

	return response, nil
}

func makeDNSQuery(qname string, qtype uint16, recurse bool) *dns.Msg {
	ret := new(dns.Msg)
	ret.SetQuestion(qname, qtype)
	// TODO: option to enable/disable DNSSEC
	ret.SetEdns0(1232, false)
	ret.RecursionDesired = recurse
	return ret
}

// ChopOff
func DNSNameChopOff(fqdn string) iter.Seq[string] {
	return func(yield func(string) bool) {
		if fqdn == "" {
			return
		}

		for _, index := range dns.Split(fqdn) {
			if !yield(fqdn[index:]) {
				return
			}
		}
	}
}

// Follow all CNAMEs (if any)
func getFinalCNAMETarget(response *dns.Msg, initialName string) string {
	for _, rr := range response.Answer {
		if cn, ok := rr.(*dns.CNAME); ok {
			if strings.EqualFold(cn.Hdr.Name, initialName) {
				// CNAMEs don't *have* to be in order
				// (https://datatracker.ietf.org/doc/draft-jabley-dnsop-ordered-answer-section/00/)
				return getFinalCNAMETarget(response, initialName)
			}
		}
	}

	return initialName
}
