package dns01

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"

	"tls-broker/internal/core/coretest"
)

func txtSet(name string, ttl int64, values ...string) *types.ResourceRecordSet {
	rs := &types.ResourceRecordSet{Name: aws.String(name), Type: types.RRTypeTxt, TTL: aws.Int64(ttl)}
	for _, v := range values {
		rs.ResourceRecords = append(rs.ResourceRecords, types.ResourceRecord{Value: aws.String(QuoteTXT(v))})
	}
	return rs
}

func change(f *FakeRoute53, zone string, changes ...types.Change) (*route53.ChangeResourceRecordSetsOutput, error) {
	return f.ChangeResourceRecordSets(context.Background(), &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zone), ChangeBatch: &types.ChangeBatch{Changes: changes}})
}

func TestFakeRoute53Semantics(t *testing.T) {
	ctx := context.Background()
	clock := coretest.NewFakeClock()
	f := NewFakeRoute53(clock)
	f.AddZone("/hostedzone/Z1", "example.com")
	f.SetSyncDelay(30 * time.Second)
	f.SetPublicDelay(10 * time.Second)
	name := "_acme-challenge.foo.example.com."

	out, err := change(f, "Z1", types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: txtSet(name, 60, "a", "b")})
	if err != nil {
		t.Fatal(err)
	}
	if out.ChangeInfo.Status != types.ChangeStatusPending {
		t.Fatalf("status = %s", out.ChangeInfo.Status)
	}
	if got := f.TXT(name); len(got) != 2 {
		t.Fatalf("API view = %v", got)
	}
	if got, _ := f.LookupTXT(ctx, name); len(got) != 0 {
		t.Fatalf("public view before delay = %v", got)
	}
	clock.Advance(10 * time.Second)
	if got, _ := f.LookupTXT(ctx, "_ACME-challenge.foo.example.com"); len(got) != 2 {
		t.Fatalf("public view after delay = %v", got)
	}
	clock.Advance(20 * time.Second)
	gc, err := f.GetChange(ctx, &route53.GetChangeInput{Id: out.ChangeInfo.Id})
	if err != nil || gc.ChangeInfo.Status != types.ChangeStatusInsync {
		t.Fatalf("GetChange = %+v, %v", gc, err)
	}

	// CREATE of an existing set and a DELETE that does not match fail the
	// whole batch, which changes nothing.
	_, err = change(f, "Z1",
		types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: txtSet(name, 60, "a", "b")},
		types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: txtSet(name, 60, "c")},
		types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: txtSet(name, 60, "d")})
	var icb *types.InvalidChangeBatch
	if !errors.As(err, &icb) {
		t.Fatalf("err = %v, want InvalidChangeBatch", err)
	}
	if _, err := change(f, "Z1", types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: txtSet(name, 300, "a", "b")}); !errors.As(err, &icb) {
		t.Fatalf("delete with wrong TTL: err = %v", err)
	}
	if got := f.TXT(name); len(got) != 2 {
		t.Fatalf("failed batch changed data: %v", got)
	}
	unquoted := &types.ResourceRecordSet{Name: aws.String("x.example.com"), Type: types.RRTypeTxt, TTL: aws.Int64(1),
		ResourceRecords: []types.ResourceRecord{{Value: aws.String("bare")}}}
	if _, err := change(f, "Z1", types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: unquoted}); !errors.As(err, &icb) {
		t.Fatalf("unquoted TXT accepted: %v", err)
	}
	if _, err := change(f, "Z1", types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: txtSet("x.example.org", 60, "v")}); !errors.As(err, &icb) {
		t.Fatalf("record outside the zone accepted: %v", err)
	}
	if _, err := change(f, "ZX", types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: txtSet(name, 60, "v")}); err == nil {
		t.Fatal("unknown zone accepted")
	}

	list, err := f.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{HostedZoneId: aws.String("Z1"),
		StartRecordName: aws.String(name), StartRecordType: types.RRTypeTxt, MaxItems: aws.Int32(1)})
	if err != nil || len(list.ResourceRecordSets) != 1 || aws.ToString(list.ResourceRecordSets[0].Name) != name {
		t.Fatalf("list = %+v, %v", list, err)
	}

	// Faults fire in order and are counted.
	f.Throttle(OpGetChange, 1)
	if _, err := f.GetChange(ctx, &route53.GetChangeInput{Id: out.ChangeInfo.Id}); apiCode(err) != "ThrottlingException" || !retryable(err) {
		t.Fatalf("throttle: err = %v", err)
	}
	f.Hang(OpList, 1)
	hctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.ListResourceRecordSets(hctx, &route53.ListResourceRecordSetsInput{HostedZoneId: aws.String("Z1")}); err == nil {
		t.Fatal("hang returned without error")
	}
	if f.Calls(OpGetChange) != 2 {
		t.Fatalf("calls = %d", f.Calls(OpGetChange))
	}

	// The resolver adapter reads the public view.
	r := f.Resolver(nil)
	if got, _ := r.LookupTXT(ctx, name); len(got) != 2 {
		t.Fatalf("resolver view = %v", got)
	}
	if a, err := r.LookupA(ctx, "foo.example.com"); a != nil || err != nil {
		t.Fatalf("LookupA without base = %v, %v", a, err)
	}
}

func TestRetryableClassification(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{&types.ThrottlingException{}, true},
		{&types.PriorRequestNotComplete{}, true},
		{&types.InvalidChangeBatch{}, false},
		{&types.InvalidInput{}, false},
		{&types.NoSuchHostedZone{}, false},
		{errors.New("connection reset"), true},
		{context.DeadlineExceeded, true},
		{context.Canceled, false},
	}
	for _, c := range cases {
		if got := retryable(c.err); got != c.want {
			t.Errorf("retryable(%T %v) = %v", c.err, c.err, got)
		}
	}
}
