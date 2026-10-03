package main

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"
	"github.com/miekg/dns"

	"tls-broker/internal/dns01"
)

const r53NS = "https://route53.amazonaws.com/doc/2013-04-01/"

// server serves the Route53 REST-XML operations the broker's DNS-01 engine
// uses, over api, and a DoH endpoint answering TXT from fake's public view.
type server struct {
	api  dns01.Route53API
	fake *dns01.FakeRoute53
	log  *slog.Logger
}

func (s *server) routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /2013-04-01/hostedzone/{id}/rrset", s.change)
	m.HandleFunc("POST /2013-04-01/hostedzone/{id}/rrset/", s.change)
	m.HandleFunc("GET /2013-04-01/hostedzone/{id}/rrset", s.list)
	m.HandleFunc("GET /2013-04-01/hostedzone/{id}/rrset/", s.list)
	m.HandleFunc("GET /2013-04-01/hostedzone/{id}", s.getZone)
	m.HandleFunc("GET /2013-04-01/change/{id}", s.getChange)
	m.HandleFunc("/dns-query", s.doh)
	return m
}

// ---- XML shapes -------------------------------------------------------------

type xmlRecord struct {
	Value string `xml:"Value"`
}

type xmlRRSet struct {
	Name            string      `xml:"Name"`
	Type            string      `xml:"Type"`
	TTL             *int64      `xml:"TTL,omitempty"`
	ResourceRecords []xmlRecord `xml:"ResourceRecords>ResourceRecord"`
}

type xmlChangeInfo struct {
	ID          string `xml:"Id"`
	Status      string `xml:"Status"`
	SubmittedAt string `xml:"SubmittedAt"`
}

type changeRequest struct {
	XMLName xml.Name `xml:"ChangeResourceRecordSetsRequest"`
	Changes []struct {
		Action string   `xml:"Action"`
		RRSet  xmlRRSet `xml:"ResourceRecordSet"`
	} `xml:"ChangeBatch>Changes>Change"`
}

type changeResponse struct {
	XMLName    xml.Name      `xml:"ChangeResourceRecordSetsResponse"`
	NS         string        `xml:"xmlns,attr"`
	ChangeInfo xmlChangeInfo `xml:"ChangeInfo"`
}

type getChangeResponse struct {
	XMLName    xml.Name      `xml:"GetChangeResponse"`
	NS         string        `xml:"xmlns,attr"`
	ChangeInfo xmlChangeInfo `xml:"ChangeInfo"`
}

type listResponse struct {
	XMLName        xml.Name   `xml:"ListResourceRecordSetsResponse"`
	NS             string     `xml:"xmlns,attr"`
	RRSets         []xmlRRSet `xml:"ResourceRecordSets>ResourceRecordSet"`
	IsTruncated    bool       `xml:"IsTruncated"`
	NextRecordName string     `xml:"NextRecordName,omitempty"`
	NextRecordType string     `xml:"NextRecordType,omitempty"`
	MaxItems       int32      `xml:"MaxItems"`
}

type getZoneResponse struct {
	XMLName xml.Name `xml:"GetHostedZoneResponse"`
	NS      string   `xml:"xmlns,attr"`
	Zone    struct {
		ID              string `xml:"Id"`
		Name            string `xml:"Name"`
		CallerReference string `xml:"CallerReference"`
		PrivateZone     bool   `xml:"Config>PrivateZone"`
	} `xml:"HostedZone"`
}

type errorResponse struct {
	XMLName xml.Name `xml:"ErrorResponse"`
	NS      string   `xml:"xmlns,attr"`
	Error   struct {
		Type    string `xml:"Type"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
	RequestID string `xml:"RequestId"`
}

func changeInfo(ci *types.ChangeInfo) xmlChangeInfo {
	return xmlChangeInfo{ID: aws.ToString(ci.Id), Status: string(ci.Status),
		SubmittedAt: aws.ToTime(ci.SubmittedAt).UTC().Format(time.RFC3339)}
}

func toXMLRRSet(rs types.ResourceRecordSet) xmlRRSet {
	out := xmlRRSet{Name: aws.ToString(rs.Name), Type: string(rs.Type), TTL: rs.TTL}
	for _, r := range rs.ResourceRecords {
		out.ResourceRecords = append(out.ResourceRecords, xmlRecord{Value: aws.ToString(r.Value)})
	}
	return out
}

// ---- handlers ---------------------------------------------------------------

func (s *server) writeXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, xml.Header)
	_ = xml.NewEncoder(w).Encode(v)
}

func (s *server) fail(w http.ResponseWriter, err error) {
	s.log.Warn("route53 call failed", "err", err)
	e := errorResponse{NS: r53NS, RequestID: "r53mock"}
	e.Error.Type, e.Error.Code, e.Error.Message = "Sender", "InvalidInput", err.Error()
	status := http.StatusBadRequest
	var ae smithy.APIError
	if errors.As(err, &ae) {
		e.Error.Code, e.Error.Message = ae.ErrorCode(), ae.ErrorMessage()
		switch ae.ErrorCode() {
		case "NoSuchHostedZone", "NoSuchChange":
			status = http.StatusNotFound
		case "Throttling", "ThrottlingException", "PriorRequestNotComplete":
			status = http.StatusBadRequest
		}
		if ae.ErrorFault() == smithy.FaultServer {
			e.Error.Type, status = "Receiver", http.StatusInternalServerError
		}
	}
	s.writeXML(w, status, e)
}

func (s *server) change(w http.ResponseWriter, r *http.Request) {
	var req changeRequest
	if err := xml.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		s.fail(w, fmt.Errorf("bad request body: %w", err))
		return
	}
	in := &route53.ChangeResourceRecordSetsInput{HostedZoneId: aws.String(r.PathValue("id")), ChangeBatch: &types.ChangeBatch{}}
	for _, c := range req.Changes {
		rs := types.ResourceRecordSet{Name: aws.String(c.RRSet.Name), Type: types.RRType(c.RRSet.Type), TTL: c.RRSet.TTL}
		for _, v := range c.RRSet.ResourceRecords {
			rs.ResourceRecords = append(rs.ResourceRecords, types.ResourceRecord{Value: aws.String(v.Value)})
		}
		in.ChangeBatch.Changes = append(in.ChangeBatch.Changes, types.Change{Action: types.ChangeAction(c.Action), ResourceRecordSet: &rs})
	}
	out, err := s.api.ChangeResourceRecordSets(r.Context(), in)
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, c := range in.ChangeBatch.Changes {
		s.log.Info("change", "zone", r.PathValue("id"), "action", c.Action, "name", aws.ToString(c.ResourceRecordSet.Name),
			"type", c.ResourceRecordSet.Type, "records", len(c.ResourceRecordSet.ResourceRecords))
	}
	s.writeXML(w, http.StatusOK, changeResponse{NS: r53NS, ChangeInfo: changeInfo(out.ChangeInfo)})
}

func (s *server) getChange(w http.ResponseWriter, r *http.Request) {
	out, err := s.api.GetChange(r.Context(), &route53.GetChangeInput{Id: aws.String(r.PathValue("id"))})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.writeXML(w, http.StatusOK, getChangeResponse{NS: r53NS, ChangeInfo: changeInfo(out.ChangeInfo)})
}

func (s *server) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	in := &route53.ListResourceRecordSetsInput{HostedZoneId: aws.String(r.PathValue("id"))}
	if v := q.Get("name"); v != "" {
		in.StartRecordName = aws.String(v)
	}
	if v := q.Get("type"); v != "" {
		in.StartRecordType = types.RRType(v)
	}
	if v := q.Get("maxitems"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			s.fail(w, fmt.Errorf("bad maxitems %q", v))
			return
		}
		in.MaxItems = aws.Int32(int32(n))
	}
	out, err := s.api.ListResourceRecordSets(r.Context(), in)
	if err != nil {
		s.fail(w, err)
		return
	}
	resp := listResponse{NS: r53NS, IsTruncated: out.IsTruncated, MaxItems: aws.ToInt32(out.MaxItems),
		NextRecordName: aws.ToString(out.NextRecordName), NextRecordType: string(out.NextRecordType)}
	for _, rs := range out.ResourceRecordSets {
		resp.RRSets = append(resp.RRSets, toXMLRRSet(rs))
	}
	s.writeXML(w, http.StatusOK, resp)
}

func (s *server) getZone(w http.ResponseWriter, r *http.Request) {
	out, err := s.api.GetHostedZone(r.Context(), &route53.GetHostedZoneInput{Id: aws.String(r.PathValue("id"))})
	if err != nil {
		s.fail(w, err)
		return
	}
	resp := getZoneResponse{NS: r53NS}
	hz := out.HostedZone
	resp.Zone.ID, resp.Zone.Name, resp.Zone.CallerReference = aws.ToString(hz.Id), aws.ToString(hz.Name), aws.ToString(hz.CallerReference)
	if hz.Config != nil {
		resp.Zone.PrivateZone = hz.Config.PrivateZone
	}
	s.writeXML(w, http.StatusOK, resp)
}

// doh answers RFC 8484 queries (GET ?dns= and POST): TXT from the fake's
// public view, NXDOMAIN for everything else.
func (s *server) doh(w http.ResponseWriter, r *http.Request) {
	var wire []byte
	var err error
	switch r.Method {
	case http.MethodGet:
		wire, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
	case http.MethodPost:
		wire, err = io.ReadAll(io.LimitReader(r.Body, 65535))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := new(dns.Msg)
	if err == nil {
		err = q.Unpack(wire)
	}
	if err != nil || len(q.Question) != 1 {
		http.Error(w, "bad DNS query", http.StatusBadRequest)
		return
	}
	m := new(dns.Msg)
	m.SetReply(q)
	m.RecursionAvailable = true
	qq := q.Question[0]
	if qq.Qtype == dns.TypeTXT {
		vals, _ := s.fake.LookupTXT(r.Context(), strings.TrimSuffix(qq.Name, "."))
		for _, v := range vals {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: qq.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{v}})
		}
	}
	if len(m.Answer) == 0 {
		m.Rcode = dns.RcodeNameError
	}
	out, err := m.Pack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(out)
}
