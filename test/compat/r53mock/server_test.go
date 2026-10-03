package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"
	"github.com/miekg/dns"

	"tls-broker/internal/core"
	"tls-broker/internal/dns01"
)

// TestRoute53WithRealClient drives the mock with the broker's own Route53
// client builder, pointed at it through AWS_ENDPOINT_URL_ROUTE_53 exactly as
// test/compat/run.sh does for the broker container.
func TestRoute53WithRealClient(t *testing.T) {
	fake := dns01.NewFakeRoute53(nil)
	fake.AddZone("ZCOMPAT", "compat.test")
	ts := httptest.NewServer((&server{api: fake, fake: fake, log: slog.New(slog.NewTextHandler(io.Discard, nil))}).routes())
	defer ts.Close()

	t.Setenv("AWS_ENDPOINT_URL_ROUTE_53", ts.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "compat")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "compat")
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
	ctx := context.Background()
	c, err := dns01.NewRoute53Client(ctx, core.Route53Config{Region: "us-east-1"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	hz, err := c.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: aws.String("ZCOMPAT")})
	if err != nil || aws.ToString(hz.HostedZone.Name) != "compat.test." || hz.HostedZone.Config.PrivateZone {
		t.Fatalf("GetHostedZone: %+v %v", hz, err)
	}
	ch, err := c.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String("/hostedzone/ZCOMPAT"),
		ChangeBatch: &types.ChangeBatch{Changes: []types.Change{{Action: types.ChangeActionUpsert,
			ResourceRecordSet: &types.ResourceRecordSet{Name: aws.String("_acme-challenge.www.compat.test."), Type: types.RRTypeTxt,
				TTL: aws.Int64(60), ResourceRecords: []types.ResourceRecord{{Value: aws.String(`"v1"`)}, {Value: aws.String(`"v2"`)}}}}}},
	})
	if err != nil || ch.ChangeInfo.Status != types.ChangeStatusInsync || aws.ToString(ch.ChangeInfo.Id) == "" || ch.ChangeInfo.SubmittedAt == nil {
		t.Fatalf("Change: %+v %v", ch, err)
	}
	gc, err := c.GetChange(ctx, &route53.GetChangeInput{Id: ch.ChangeInfo.Id})
	if err != nil || gc.ChangeInfo.Status != types.ChangeStatusInsync {
		t.Fatalf("GetChange: %+v %v", gc, err)
	}
	ls, err := c.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{HostedZoneId: aws.String("ZCOMPAT"),
		StartRecordName: aws.String("_acme-challenge.www.compat.test."), StartRecordType: types.RRTypeTxt, MaxItems: aws.Int32(1)})
	if err != nil || len(ls.ResourceRecordSets) != 1 || len(ls.ResourceRecordSets[0].ResourceRecords) != 2 ||
		aws.ToInt64(ls.ResourceRecordSets[0].TTL) != 60 || aws.ToString(ls.ResourceRecordSets[0].ResourceRecords[1].Value) != `"v2"` {
		t.Fatalf("List: %+v %v", ls, err)
	}

	// A failed batch keeps its Route53 error code, which the engine reads.
	_, err = c.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String("ZCOMPAT"),
		ChangeBatch: &types.ChangeBatch{Changes: []types.Change{{Action: types.ChangeActionDelete,
			ResourceRecordSet: &types.ResourceRecordSet{Name: aws.String("_acme-challenge.www.compat.test."), Type: types.RRTypeTxt,
				TTL: aws.Int64(60), ResourceRecords: []types.ResourceRecord{{Value: aws.String(`"other"`)}}}}}},
	})
	var ae smithy.APIError
	if !errors.As(err, &ae) || ae.ErrorCode() != "InvalidChangeBatch" {
		t.Fatalf("bad delete: %v", err)
	}
	if _, err := c.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: aws.String("ZNOPE")}); !errors.As(err, &ae) || ae.ErrorCode() != "NoSuchHostedZone" {
		t.Fatalf("unknown zone: %v", err)
	}

	// DoH: the TXT values are visible; other names are NXDOMAIN.
	ask := func(name string, typ uint16) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(name, typ)
		wire, _ := q.Pack()
		resp, err := http.Post(ts.URL+"/dns-query", "application/dns-message", bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		m := new(dns.Msg)
		if err := m.Unpack(b); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := ask("_acme-challenge.www.compat.test.", dns.TypeTXT); len(m.Answer) != 2 || m.Answer[0].(*dns.TXT).Txt[0] != "v1" {
		t.Fatalf("doh TXT: %v", m)
	}
	if m := ask("www.compat.test.", dns.TypeA); m.Rcode != dns.RcodeNameError {
		t.Fatalf("doh A: %v", m)
	}
}
