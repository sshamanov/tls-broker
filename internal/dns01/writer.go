package dns01

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"

	"tls-broker/internal/core"
)

const (
	// maxBatchRecords bounds the record names written in one change; Route53
	// allows 1000 values per batch.
	maxBatchRecords = 50
	// conflictRetries is how often a batch is re-planned after Route53
	// rejected it because an RRset changed under us.
	conflictRetries = 3
	retryInitial    = 500 * time.Millisecond
	retryMax        = 10 * time.Second
)

// zoneWriter is the serialized write queue of one hosted zone. Callers add
// record names; one goroutine (started on demand, exiting when the queue is
// empty) writes every queued name in one change and answers all of their
// callers at once.
type zoneWriter struct {
	e      *Engine
	zoneID string

	mu      sync.Mutex
	order   []string                      // queued record names, FIFO
	waiters map[string][]chan writeResult // record -> callers
	running bool
}

type writeResult struct {
	changeID string
	err      error
}

func (e *Engine) writer(zoneID string) *zoneWriter {
	e.mu.Lock()
	defer e.mu.Unlock()
	w, ok := e.writers[zoneID]
	if !ok {
		w = &zoneWriter{e: e, zoneID: zoneID, waiters: map[string][]chan writeResult{}}
		e.writers[zoneID] = w
	}
	return w
}

// write makes Route53 hold the desired RRset of rec (as of when the write
// runs) and returns the ID of the change that last wrote the record, or ""
// when the engine never wrote it. Returning early on ctx does not cancel the
// write.
func (e *Engine) write(ctx context.Context, zoneID, rec string) (string, error) {
	w := e.writer(zoneID)
	ch := make(chan writeResult, 1)
	w.mu.Lock()
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		w.mu.Unlock()
		return "", ErrClosed
	}
	if !w.running {
		w.running = true
		e.wg.Add(1)
		go w.run()
	}
	e.mu.Unlock()
	if _, ok := w.waiters[rec]; !ok {
		w.order = append(w.order, rec)
	}
	w.waiters[rec] = append(w.waiters[rec], ch)
	w.mu.Unlock()
	select {
	case r := <-ch:
		return r.changeID, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// queued returns the number of record names waiting for the next batch.
func (w *zoneWriter) queued() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.order)
}

func (w *zoneWriter) run() {
	defer w.e.wg.Done()
	for {
		w.mu.Lock()
		if len(w.order) == 0 {
			w.running = false
			w.mu.Unlock()
			return
		}
		n := min(len(w.order), maxBatchRecords)
		batch := slices.Clone(w.order[:n])
		w.order = w.order[n:]
		waiters := make(map[string][]chan writeResult, n)
		for _, rec := range batch {
			waiters[rec] = w.waiters[rec]
			delete(w.waiters, rec)
		}
		w.mu.Unlock()

		changeID, err := w.flush(batch)
		for _, rec := range batch {
			r := writeResult{err: err}
			if err == nil {
				r.changeID = w.e.noteChange(w.zoneID, rec, changeID)
			}
			for _, ch := range waiters[rec] {
				ch <- r
			}
		}
	}
}

// noteChange remembers id (if any) as the last change of the record and
// returns the record's last change.
func (e *Engine) noteChange(zoneID, rec, id string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	k := recordKey(zoneID, rec)
	if id != "" {
		e.lastChange[k] = id
	}
	return e.lastChange[k]
}

// flush writes one batch, bounded by ChangeTimeout. It returns the submitted
// change ID, or "" when Route53 already matched.
func (w *zoneWriter) flush(records []string) (string, error) {
	e := w.e
	cfg := e.route53()
	ctx, cancel := clockTimeout(e.base, e.clock, cfg.ChangeTimeout,
		fmt.Errorf("%w: write to zone %s took longer than %s", ErrChangeTimeout, w.zoneID, cfg.ChangeTimeout))
	defer cancel()
	for attempt := 1; ; attempt++ {
		changes, err := w.plan(ctx, records, cfg)
		if err != nil {
			return "", err
		}
		if len(changes) == 0 {
			return "", nil
		}
		var out *route53.ChangeResourceRecordSetsOutput
		err = e.retry(ctx, func(ctx context.Context) error {
			var err error
			out, err = e.api.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
				HostedZoneId: aws.String(w.zoneID),
				ChangeBatch: &types.ChangeBatch{
					Comment: aws.String("tls-broker dns-01"),
					Changes: changes,
				},
			})
			return err
		})
		if err == nil {
			if out == nil || out.ChangeInfo == nil || out.ChangeInfo.Id == nil {
				return "", errors.New("route53: change without change info")
			}
			return aws.ToString(out.ChangeInfo.Id), nil
		}
		if apiCode(err) == "InvalidChangeBatch" && attempt < conflictRetries {
			continue // an RRset changed between read and write; plan again
		}
		return "", fmt.Errorf("route53: change zone %s: %w", w.zoneID, err)
	}
}

// plan computes the changes that make each record hold its desired RRset.
func (w *zoneWriter) plan(ctx context.Context, records []string, cfg core.Route53Config) ([]types.Change, error) {
	e := w.e
	var changes []types.Change
	for _, rec := range records {
		rows, err := e.store.ListByRecord(ctx, w.zoneID, rec)
		if err != nil {
			return nil, fmt.Errorf("dns01: list challenges of %s: %w", rec, err)
		}
		owned := map[string]bool{}
		var wanted []string
		for _, ch := range rows {
			owned[ch.Value] = true
			if ch.State.WantsRecord() && !slices.Contains(wanted, ch.Value) {
				wanted = append(wanted, ch.Value)
			}
		}
		cur, err := w.read(ctx, rec)
		if err != nil {
			return nil, err
		}

		// Desired: every current value the broker does not own, then the
		// wanted values, without duplicates.
		var raw []string
		have := map[string]bool{}
		curVals := map[string]bool{}
		if cur != nil {
			for _, r := range cur.ResourceRecords {
				v, err := UnquoteTXT(aws.ToString(r.Value))
				if err != nil { // not ours to judge: keep it verbatim
					raw = append(raw, aws.ToString(r.Value))
					continue
				}
				curVals[v] = true
				if !owned[v] && !have[v] {
					have[v] = true
					raw = append(raw, aws.ToString(r.Value))
				}
			}
		}
		for _, v := range wanted {
			if !have[v] {
				have[v] = true
				raw = append(raw, QuoteTXT(v))
			}
		}
		if cur != nil && len(have) == len(curVals) && len(raw) == len(cur.ResourceRecords) && sameKeys(have, curVals) {
			continue // already as desired
		}
		if cur == nil && len(raw) == 0 {
			continue
		}
		if cur != nil {
			changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: cur})
		}
		if len(raw) > 0 {
			rrs := make([]types.ResourceRecord, 0, len(raw))
			for _, r := range raw {
				rrs = append(rrs, types.ResourceRecord{Value: aws.String(r)})
			}
			changes = append(changes, types.Change{Action: types.ChangeActionCreate, ResourceRecordSet: &types.ResourceRecordSet{
				Name: aws.String(fqdn(rec)), Type: types.RRTypeTxt,
				TTL: aws.Int64(int64(cfg.TTL / time.Second)), ResourceRecords: rrs,
			}})
		}
	}
	return changes, nil
}

func sameKeys(a, b map[string]bool) bool {
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// read returns the current TXT RRset of rec, or nil when there is none.
func (w *zoneWriter) read(ctx context.Context, rec string) (*types.ResourceRecordSet, error) {
	var out *route53.ListResourceRecordSetsOutput
	err := w.e.retry(ctx, func(ctx context.Context) error {
		var err error
		out, err = w.e.api.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
			HostedZoneId:    aws.String(w.zoneID),
			StartRecordName: aws.String(fqdn(rec)),
			StartRecordType: types.RRTypeTxt,
			MaxItems:        aws.Int32(1),
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("route53: read %s in zone %s: %w", rec, w.zoneID, err)
	}
	for _, rs := range out.ResourceRecordSets {
		if unfqdn(aws.ToString(rs.Name)) == rec && rs.Type == types.RRTypeTxt {
			return &rs, nil
		}
	}
	return nil, nil
}

// changeStatus returns the status of a submitted change.
func (e *Engine) changeStatus(ctx context.Context, id string) (types.ChangeStatus, error) {
	ctx, cancel := clockTimeout(ctx, e.clock, e.callTimeout, errCallTimeout)
	defer cancel()
	out, err := e.api.GetChange(ctx, &route53.GetChangeInput{Id: aws.String(strings.TrimPrefix(id, "/change/"))})
	if err != nil {
		return "", err
	}
	if out.ChangeInfo == nil {
		return "", errors.New("route53: GetChange without change info")
	}
	return out.ChangeInfo.Status, nil
}

func (e *Engine) verifyZone(ctx context.Context, z core.ZoneConfig) error {
	id := hostedZoneID(z.HostedZoneID)
	var out *route53.GetHostedZoneOutput
	err := e.retry(ctx, func(ctx context.Context) error {
		var err error
		out, err = e.api.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: aws.String(id)})
		return err
	})
	if err != nil {
		return fmt.Errorf("zone %s (%s): %w", z.Name, id, err)
	}
	if out.HostedZone == nil || unfqdn(aws.ToString(out.HostedZone.Name)) != strings.ToLower(z.Name) {
		got := ""
		if out.HostedZone != nil {
			got = aws.ToString(out.HostedZone.Name)
		}
		return fmt.Errorf("zone %s: hosted zone %s is %q", z.Name, id, got)
	}
	if out.HostedZone.Config != nil && out.HostedZone.Config.PrivateZone {
		return fmt.Errorf("zone %s: hosted zone %s is private; public DNS cannot see it", z.Name, id)
	}
	return nil
}

var errCallTimeout = errors.New("route53 call timed out")

// retry runs op until it succeeds, fails permanently, or ctx ends. Each
// attempt gets CallTimeout; throttling, server and transport errors and
// timed-out attempts are retried with exponential backoff on the clock.
func (e *Engine) retry(ctx context.Context, op func(ctx context.Context) error) error {
	delay := retryInitial
	for {
		cctx, cancel := clockTimeout(ctx, e.clock, e.callTimeout, errCallTimeout)
		err := op(cctx)
		timedOut := errors.Is(context.Cause(cctx), errCallTimeout)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("%w (last error: %v)", context.Cause(ctx), err)
		}
		if timedOut {
			err = fmt.Errorf("%w: %v", errCallTimeout, err)
		} else if !retryable(err) {
			return err
		}
		if core.Sleep(ctx, e.clock, delay) != nil {
			return fmt.Errorf("%w (last error: %v)", context.Cause(ctx), err)
		}
		delay = min(delay*2, retryMax)
	}
}

// apiCode returns the Route53 error code of err, or "".
func apiCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

// retryable reports whether a failed call may succeed when repeated.
func retryable(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "Throttling", "ThrottlingException", "PriorRequestNotComplete", "RequestLimitExceeded",
			"ServiceUnavailable", "InternalFailure", "InternalError", "RequestTimeout":
			return true
		}
		return ae.ErrorFault() == smithy.FaultServer
	}
	// Transport failures and timeouts surface without an API code.
	return !errors.Is(err, context.Canceled)
}

// clockTimeout returns a context that is cancelled with cause once d has
// passed on clock (or when parent is done).
func clockTimeout(parent context.Context, clock core.Clock, d time.Duration, cause error) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	stop := make(chan struct{})
	timer := clock.After(d)
	go func() {
		select {
		case <-timer:
			cancel(cause)
		case <-stop:
		case <-ctx.Done():
		}
	}()
	var once sync.Once
	return ctx, func() {
		once.Do(func() { close(stop); cancel(context.Canceled) })
	}
}
