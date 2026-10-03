package dns01

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"

	"tls-broker/internal/core"
)

// Operation names used by FakeRoute53 fault injection and call counters.
const (
	OpChange        = "ChangeResourceRecordSets"
	OpList          = "ListResourceRecordSets"
	OpGetChange     = "GetChange"
	OpGetHostedZone = "GetHostedZone"
	OpListZones     = "ListHostedZones"
)

// maxZonesPerPage is the largest page ListHostedZones returns, like the real
// API's limit of 100.
const maxZonesPerPage = 100

// FakeRoute53 is an in-memory Route53 implementing Route53API with the
// semantics the engine relies on:
//
//   - hosted zones holding RRsets; a change batch is validated and applied
//     atomically (CREATE of an existing RRset, or DELETE that does not match
//     the current RRset exactly, fails the whole batch with
//     InvalidChangeBatch); TXT values must be quoted;
//   - changes are PENDING until SyncDelay has passed on the clock, then
//     INSYNC;
//   - a public view of TXT records that lags each change by PublicDelay
//     (independent of SyncDelay), read through LookupTXT or Resolver;
//   - fault injection per operation (Fail, Throttle, Hang) and a hook that
//     runs inside every ChangeResourceRecordSets call (OnChange);
//   - counters: calls per operation, changes and maximum concurrent changes
//     per zone.
//
// Record names are compared case-insensitively, with or without trailing
// dot. It is safe for concurrent use.
type FakeRoute53 struct {
	mu          sync.Mutex
	clock       core.Clock
	zones       map[string]*fakeZone
	changes     map[string]time.Time // change ID -> submitted at
	seq         int
	syncDelay   time.Duration
	publicDelay time.Duration
	faults      map[string][]fakeFault
	calls       map[string]int
	inflight    map[string]int // zone -> running change calls
	maxInflight map[string]int
	changeCount map[string]int
	hook        func(ctx context.Context, zoneID string) error
	zonePage    int // ListHostedZones page cap; 0 means maxZonesPerPage
}

type fakeZone struct {
	id, name string // name normalized, without trailing dot
	private  bool
	rrsets   map[rrKey]types.ResourceRecordSet
	public   []publicEntry // TXT history in submission order
}

type rrKey struct {
	name string // normalized, without trailing dot
	typ  types.RRType
}

// publicEntry says the TXT RRset at name is values from at onwards.
type publicEntry struct {
	at     time.Time
	name   string
	values []string // unquoted; nil when deleted
}

type fakeFault struct {
	err  error
	hang bool
}

var _ Route53API = (*FakeRoute53)(nil)

// NewFakeRoute53 returns an empty fake with no delays. clock nil uses the
// system clock.
func NewFakeRoute53(clock core.Clock) *FakeRoute53 {
	if clock == nil {
		clock = core.SystemClock{}
	}
	return &FakeRoute53{
		clock: clock, zones: map[string]*fakeZone{}, changes: map[string]time.Time{},
		faults: map[string][]fakeFault{}, calls: map[string]int{}, inflight: map[string]int{},
		maxInflight: map[string]int{}, changeCount: map[string]int{},
	}
}

func fakeName(n string) string { return unfqdn(n) }

// AddZone adds a public hosted zone. id may carry the "/hostedzone/" prefix.
func (f *FakeRoute53) AddZone(id, name string) { f.addZone(id, name, false) }

// AddPrivateZone adds a private hosted zone.
func (f *FakeRoute53) AddPrivateZone(id, name string) { f.addZone(id, name, true) }

func (f *FakeRoute53) addZone(id, name string, private bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id = hostedZoneID(id)
	f.zones[id] = &fakeZone{id: id, name: fakeName(name), private: private, rrsets: map[rrKey]types.ResourceRecordSet{}}
}

// SetZonePageSize caps the hosted zones one ListHostedZones call returns
// (tests use it to exercise pagination); n <= 0 restores the default of 100.
func (f *FakeRoute53) SetZonePageSize(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.zonePage = n
}

// SetSyncDelay sets how long new changes stay PENDING.
func (f *FakeRoute53) SetSyncDelay(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncDelay = d
}

// SetPublicDelay sets how long new changes take to show in the public view.
func (f *FakeRoute53) SetPublicDelay(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.publicDelay = d
}

// Fail makes the next `times` calls of op return err.
func (f *FakeRoute53) Fail(op string, err error, times int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for range times {
		f.faults[op] = append(f.faults[op], fakeFault{err: err})
	}
}

// ClearFaults drops every injected fault that has not fired yet.
func (f *FakeRoute53) ClearFaults() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.faults = map[string][]fakeFault{}
}

// Throttle makes the next `times` calls of op fail with a Route53
// ThrottlingException.
func (f *FakeRoute53) Throttle(op string, times int) {
	f.Fail(op, &types.ThrottlingException{Message: aws.String("Rate exceeded")}, times)
}

// Hang makes the next `times` calls of op block until their context is
// done (a Route53 timeout), then return the context error.
func (f *FakeRoute53) Hang(op string, times int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for range times {
		f.faults[op] = append(f.faults[op], fakeFault{hang: true})
	}
}

// OnChange installs a hook run at the start of every ChangeResourceRecordSets
// call (after fault injection), while the call counts as running for its
// zone. It may block; a non-nil error fails the call. nil removes it.
func (f *FakeRoute53) OnChange(h func(ctx context.Context, zoneID string) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = h
}

// Calls returns how often op was called (failed calls included).
func (f *FakeRoute53) Calls(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[op]
}

// Changes returns how many change batches were applied to the zone.
func (f *FakeRoute53) Changes(zoneID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.changeCount[hostedZoneID(zoneID)]
}

// MaxConcurrentChanges returns the largest number of ChangeResourceRecordSets
// calls that were running at the same time for the zone.
func (f *FakeRoute53) MaxConcurrentChanges(zoneID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxInflight[hostedZoneID(zoneID)]
}

// SetTXT sets the TXT RRset at name as if someone else had written it (for
// example a foreign value), visible publicly at once. Values are unquoted; no
// values deletes the RRset.
func (f *FakeRoute53) SetTXT(name string, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := fakeName(name)
	z := f.zoneOf(n)
	if z == nil {
		panic("dns01: FakeRoute53.SetTXT: no zone for " + name)
	}
	k := rrKey{n, types.RRTypeTxt}
	if len(values) == 0 {
		delete(z.rrsets, k)
		z.public = append(z.public, publicEntry{at: f.clock.Now(), name: n})
		return
	}
	rrs := make([]types.ResourceRecord, 0, len(values))
	for _, v := range values {
		rrs = append(rrs, types.ResourceRecord{Value: aws.String(QuoteTXT(v))})
	}
	z.rrsets[k] = types.ResourceRecordSet{Name: aws.String(n + "."), Type: types.RRTypeTxt, TTL: aws.Int64(300), ResourceRecords: rrs}
	z.public = append(z.public, publicEntry{at: f.clock.Now(), name: n, values: slices.Clone(values)})
}

// TXT returns the unquoted TXT values Route53 holds at name (the API view),
// in RRset order; nil when there is no RRset.
func (f *FakeRoute53) TXT(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs, ok := f.rrset(name, types.RRTypeTxt)
	if !ok {
		return nil
	}
	return txtValues(rs)
}

// RRSet returns a copy of the RRset at name and type as stored (quoted
// values, TTL).
func (f *FakeRoute53) RRSet(name string, typ types.RRType) (types.ResourceRecordSet, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs, ok := f.rrset(name, typ)
	return copyRRSet(rs), ok
}

func (f *FakeRoute53) rrset(name string, typ types.RRType) (types.ResourceRecordSet, bool) {
	n := fakeName(name)
	z := f.zoneOf(n)
	if z == nil {
		return types.ResourceRecordSet{}, false
	}
	rs, ok := z.rrsets[rrKey{n, typ}]
	return rs, ok
}

func txtValues(rs types.ResourceRecordSet) []string {
	out := make([]string, 0, len(rs.ResourceRecords))
	for _, r := range rs.ResourceRecords {
		v, err := UnquoteTXT(aws.ToString(r.Value))
		if err != nil {
			v = aws.ToString(r.Value)
		}
		out = append(out, v)
	}
	return out
}

// LookupTXT returns the publicly visible TXT values at name: the RRset as of
// the newest change whose PublicDelay has passed. The signature matches
// coretest.FakeCA.SetTXTLookup.
func (f *FakeRoute53) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n := fakeName(name)
	z := f.zoneOf(n)
	if z == nil {
		return nil, nil
	}
	now := f.clock.Now()
	var vals []string
	for _, p := range z.public {
		if p.name == n && !p.at.After(now) {
			vals = p.values
		}
	}
	return slices.Clone(vals), nil
}

// Resolver returns a core.Resolver whose TXT answers come from the public
// view of this fake and whose A and CAA answers come from base (nil: empty
// answers).
func (f *FakeRoute53) Resolver(base core.Resolver) core.Resolver {
	return &fakeTXTResolver{f: f, base: base}
}

type fakeTXTResolver struct {
	f    *FakeRoute53
	base core.Resolver
}

func (r *fakeTXTResolver) LookupA(ctx context.Context, name string) ([]netip.Addr, error) {
	if r.base == nil {
		return nil, ctx.Err()
	}
	return r.base.LookupA(ctx, name)
}

func (r *fakeTXTResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.f.LookupTXT(ctx, name)
}

func (r *fakeTXTResolver) LookupCAA(ctx context.Context, name string) ([]core.CAA, error) {
	if r.base == nil {
		return nil, ctx.Err()
	}
	return r.base.LookupCAA(ctx, name)
}

// zoneOf returns the zone holding n (longest suffix). Caller holds f.mu.
func (f *FakeRoute53) zoneOf(n string) *fakeZone {
	var best *fakeZone
	for _, z := range f.zones {
		if (n == z.name || strings.HasSuffix(n, "."+z.name)) && (best == nil || len(z.name) > len(best.name)) {
			best = z
		}
	}
	return best
}

// begin counts the call and applies injected faults. It must be called
// without f.mu held.
func (f *FakeRoute53) begin(ctx context.Context, op string) error {
	f.mu.Lock()
	f.calls[op]++
	var fault *fakeFault
	if q := f.faults[op]; len(q) > 0 {
		fault = &q[0]
		f.faults[op] = q[1:]
	}
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if fault == nil {
		return nil
	}
	if fault.hang {
		<-ctx.Done()
		return fmt.Errorf("operation %s: %w", op, ctx.Err())
	}
	return fault.err
}

func invalidBatch(format string, a ...any) error {
	return &types.InvalidChangeBatch{Message: aws.String(fmt.Sprintf(format, a...))}
}

// ChangeResourceRecordSets implements Route53API.
func (f *FakeRoute53) ChangeResourceRecordSets(ctx context.Context, in *route53.ChangeResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	zid := hostedZoneID(aws.ToString(in.HostedZoneId))
	f.mu.Lock()
	f.inflight[zid]++
	f.maxInflight[zid] = max(f.maxInflight[zid], f.inflight[zid])
	hook := f.hook
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inflight[zid]--
		f.mu.Unlock()
	}()

	if err := f.begin(ctx, OpChange); err != nil {
		return nil, err
	}
	if hook != nil {
		if err := hook(ctx, zid); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	z, ok := f.zones[zid]
	if !ok {
		return nil, &types.NoSuchHostedZone{Message: aws.String("no hosted zone " + zid)}
	}
	if in.ChangeBatch == nil || len(in.ChangeBatch.Changes) == 0 {
		return nil, invalidBatch("empty change batch")
	}
	next := make(map[rrKey]types.ResourceRecordSet, len(z.rrsets))
	for k, v := range z.rrsets {
		next[k] = v
	}
	var touched []string
	for _, c := range in.ChangeBatch.Changes {
		rs := c.ResourceRecordSet
		if rs == nil || rs.Name == nil {
			return nil, invalidBatch("change without record set")
		}
		n := fakeName(*rs.Name)
		if n != z.name && !strings.HasSuffix(n, "."+z.name) {
			return nil, invalidBatch("%s is not in zone %s", n, z.name)
		}
		if rs.Type == types.RRTypeTxt {
			for _, r := range rs.ResourceRecords {
				v := aws.ToString(r.Value)
				if !strings.HasPrefix(v, `"`) {
					return nil, invalidBatch("TXT value %s is not quoted", v)
				}
				if _, err := UnquoteTXT(v); err != nil {
					return nil, invalidBatch("bad TXT value: %v", err)
				}
			}
		}
		k := rrKey{n, rs.Type}
		cur, exists := next[k]
		switch c.Action {
		case types.ChangeActionCreate:
			if exists {
				return nil, invalidBatch("Tried to create resource record set [name='%s.', type='%s'] but it already exists", n, rs.Type)
			}
			if len(rs.ResourceRecords) == 0 {
				return nil, invalidBatch("record set without records")
			}
			next[k] = copyRRSet(*rs)
		case types.ChangeActionUpsert:
			if len(rs.ResourceRecords) == 0 {
				return nil, invalidBatch("record set without records")
			}
			next[k] = copyRRSet(*rs)
		case types.ChangeActionDelete:
			if !exists || !sameRRSet(cur, *rs) {
				return nil, invalidBatch("Tried to delete resource record set [name='%s.', type='%s'] but the values provided do not match the current values", n, rs.Type)
			}
			delete(next, k)
		default:
			return nil, invalidBatch("unknown action %q", c.Action)
		}
		if rs.Type == types.RRTypeTxt && !slices.Contains(touched, n) {
			touched = append(touched, n)
		}
	}
	z.rrsets = next
	now := f.clock.Now()
	for _, n := range touched {
		var vals []string
		if rs, ok := next[rrKey{n, types.RRTypeTxt}]; ok {
			vals = txtValues(rs)
		}
		z.public = append(z.public, publicEntry{at: now.Add(f.publicDelay), name: n, values: vals})
	}
	f.seq++
	id := fmt.Sprintf("C%08d", f.seq)
	f.changes[id] = now
	f.changeCount[zid]++
	return &route53.ChangeResourceRecordSetsOutput{ChangeInfo: f.changeInfo(id)}, nil
}

// changeInfo describes a change. Caller holds f.mu.
func (f *FakeRoute53) changeInfo(id string) *types.ChangeInfo {
	at := f.changes[id]
	st := types.ChangeStatusPending
	if !f.clock.Now().Before(at.Add(f.syncDelay)) {
		st = types.ChangeStatusInsync
	}
	return &types.ChangeInfo{Id: aws.String("/change/" + id), Status: st, SubmittedAt: aws.Time(at)}
}

// GetChange implements Route53API.
func (f *FakeRoute53) GetChange(ctx context.Context, in *route53.GetChangeInput, _ ...func(*route53.Options)) (*route53.GetChangeOutput, error) {
	if err := f.begin(ctx, OpGetChange); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	id := strings.TrimPrefix(aws.ToString(in.Id), "/change/")
	if _, ok := f.changes[id]; !ok {
		return nil, &types.NoSuchChange{Message: aws.String("no change " + id)}
	}
	return &route53.GetChangeOutput{ChangeInfo: f.changeInfo(id)}, nil
}

// ListResourceRecordSets implements Route53API. RRsets are ordered by name,
// then type; StartRecordName/StartRecordType and MaxItems are honoured.
func (f *FakeRoute53) ListResourceRecordSets(ctx context.Context, in *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	if err := f.begin(ctx, OpList); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	zid := hostedZoneID(aws.ToString(in.HostedZoneId))
	z, ok := f.zones[zid]
	if !ok {
		return nil, &types.NoSuchHostedZone{Message: aws.String("no hosted zone " + zid)}
	}
	keys := make([]rrKey, 0, len(z.rrsets))
	for k := range z.rrsets {
		keys = append(keys, k)
	}
	less := func(a, b rrKey) int {
		if c := strings.Compare(a.name, b.name); c != 0 {
			return c
		}
		return strings.Compare(string(a.typ), string(b.typ))
	}
	slices.SortFunc(keys, less)
	start := rrKey{}
	if in.StartRecordName != nil {
		start = rrKey{fakeName(*in.StartRecordName), in.StartRecordType}
	}
	limit := 300
	if in.MaxItems != nil && *in.MaxItems > 0 {
		limit = int(*in.MaxItems)
	}
	out := &route53.ListResourceRecordSetsOutput{MaxItems: aws.Int32(int32(limit))}
	for _, k := range keys {
		if less(k, start) < 0 {
			continue
		}
		if len(out.ResourceRecordSets) == limit {
			out.IsTruncated = true
			out.NextRecordName = aws.String(k.name + ".")
			out.NextRecordType = k.typ
			break
		}
		out.ResourceRecordSets = append(out.ResourceRecordSets, copyRRSet(z.rrsets[k]))
	}
	return out, nil
}

// GetHostedZone implements Route53API.
func (f *FakeRoute53) GetHostedZone(ctx context.Context, in *route53.GetHostedZoneInput, _ ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error) {
	if err := f.begin(ctx, OpGetHostedZone); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	zid := hostedZoneID(aws.ToString(in.Id))
	z, ok := f.zones[zid]
	if !ok {
		return nil, &types.NoSuchHostedZone{Message: aws.String("no hosted zone " + zid)}
	}
	return &route53.GetHostedZoneOutput{HostedZone: z.hostedZone()}, nil
}

// hostedZone describes the zone as the API does: FQDN name with trailing
// dot, "/hostedzone/" prefixed ID and the private flag.
func (z *fakeZone) hostedZone() *types.HostedZone {
	return &types.HostedZone{
		Id: aws.String("/hostedzone/" + z.id), Name: aws.String(z.name + "."), CallerReference: aws.String(z.id),
		Config: &types.HostedZoneConfig{PrivateZone: z.private},
	}
}

// ListHostedZones implements Route53API. Zones are ordered by ID; Marker
// (a zone ID, as NextMarker returns it) and MaxItems are honoured, and a
// page never exceeds the configured page cap.
func (f *FakeRoute53) ListHostedZones(ctx context.Context, in *route53.ListHostedZonesInput, _ ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	if err := f.begin(ctx, OpListZones); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := make([]string, 0, len(f.zones))
	for id := range f.zones {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	limit := maxZonesPerPage
	if f.zonePage > 0 {
		limit = f.zonePage
	}
	if in.MaxItems != nil && *in.MaxItems > 0 {
		limit = min(limit, int(*in.MaxItems))
	}
	start := hostedZoneID(aws.ToString(in.Marker))
	out := &route53.ListHostedZonesOutput{MaxItems: aws.Int32(int32(limit))}
	if start != "" {
		if _, ok := f.zones[start]; !ok {
			return nil, &types.NoSuchHostedZone{Message: aws.String("no hosted zone " + start)}
		}
		out.Marker = aws.String(start)
	}
	for _, id := range ids {
		if id < start {
			continue
		}
		if len(out.HostedZones) == limit {
			out.IsTruncated = true
			out.NextMarker = aws.String(id)
			break
		}
		out.HostedZones = append(out.HostedZones, *f.zones[id].hostedZone())
	}
	return out, nil
}

func copyRRSet(rs types.ResourceRecordSet) types.ResourceRecordSet {
	out := types.ResourceRecordSet{Name: aws.String(fakeName(aws.ToString(rs.Name)) + "."), Type: rs.Type}
	if rs.TTL != nil {
		out.TTL = aws.Int64(*rs.TTL)
	}
	for _, r := range rs.ResourceRecords {
		out.ResourceRecords = append(out.ResourceRecords, types.ResourceRecord{Value: aws.String(aws.ToString(r.Value))})
	}
	return out
}

// sameRRSet reports whether a DELETE of b matches the current a: same TTL
// and the same values in any order.
func sameRRSet(a, b types.ResourceRecordSet) bool {
	if aws.ToInt64(a.TTL) != aws.ToInt64(b.TTL) || len(a.ResourceRecords) != len(b.ResourceRecords) {
		return false
	}
	av, bv := make([]string, 0), make([]string, 0)
	for _, r := range a.ResourceRecords {
		av = append(av, aws.ToString(r.Value))
	}
	for _, r := range b.ResourceRecords {
		bv = append(bv, aws.ToString(r.Value))
	}
	slices.Sort(av)
	slices.Sort(bv)
	return slices.Equal(av, bv)
}
