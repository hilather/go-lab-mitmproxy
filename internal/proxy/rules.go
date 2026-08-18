package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/httputilx"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/rules"
	"github.com/hilather/go-lab-mitmproxy/internal/store"
)

func (s *Server) engine() *rules.Engine {
	return rules.New(s.specNow().Rules)
}

func (s *Server) matchRules(phase, host string, req *http.Request, hdr http.Header) *rules.Hit {
	hit := s.engine().Match(phase, rules.Request{
		Host:    host,
		Path:    requestPath(req),
		Method:  requestMethod(req),
		Headers: headersFrom(hdr),
	})
	if hit != nil {
		s.metrics.ruleHit(hit.Action.Type)
	}
	return hit
}

func requestMethod(req *http.Request) string {
	if req == nil {
		return ""
	}
	return req.Method
}

func requestPath(req *http.Request) string {
	if req == nil || req.URL == nil || req.URL.Path == "" {
		return "/"
	}
	return req.URL.Path
}

func (s *Server) sleepDelay(ctx context.Context, d time.Duration) bool {
	d = rules.ClampDelay(d)
	if d <= 0 {
		return true
	}
	if ctx == nil {
		ctx = context.Background()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	var stop <-chan struct{}
	if s != nil && s.ctx != nil {
		stop = s.ctx.Done()
	}
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	case <-stop:
		return false
	}
}

func applyHTTPHeaders(h http.Header, spec model.RuleHeadersSpec) {
	if h == nil {
		return
	}
	for _, name := range spec.Remove {
		h.Del(name)
	}
	if len(spec.Set) == 0 {
		return
	}
	keys := make([]string, 0, len(spec.Set))
	for k := range spec.Set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Set(k, spec.Set[k])
	}
}

func applyPatchToHeader(h http.Header, headers []model.Header) {
	if h == nil || headers == nil {
		return
	}
	for k := range h {
		h.Del(k)
	}
	for i := range headers {
		h.Add(headers[i].Name, headers[i].Value)
	}
}

func readCapped(r io.Reader, max int64) (prefix []byte, overflow bool, rest io.Reader, err error) {
	if r == nil {
		return nil, false, nil, nil
	}
	if max <= 0 {
		max = defaultMaxBodyBytes
	}
	prefix, err = io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return prefix, false, nil, err
	}
	if int64(len(prefix)) > max {
		extra := append([]byte(nil), prefix[max:]...)
		prefix = prefix[:max]
		return prefix, true, io.MultiReader(bytes.NewReader(extra), r), nil
	}
	return prefix, false, nil, nil
}

func (s *Server) maxBody() int64 {
	n := s.specNow().Store.MaxBodyBytes
	if n <= 0 {
		return defaultMaxBodyBytes
	}
	return n
}

// prepareRequestBody implements stream-vs-mutate on the request side.
func (s *Server) prepareRequestBody(req *http.Request, hit *rules.Hit) *cappedWriter {
	if req == nil || !rules.Mutates(hit) {
		return nil
	}
	max := s.maxBody()
	capw := &cappedWriter{max: int(max)}
	if req.Body == nil || req.Body == http.NoBody {
		s.maybeReplaceRequestBody(req, hit, capw, false)
		return capw
	}
	orig := req.Body
	prefix, overflow, rest, err := readCapped(orig, max)
	capw.buf = append([]byte(nil), prefix...)
	capw.truncated = overflow
	if err != nil {
		_ = orig.Close()
		req.Body = io.NopCloser(bytes.NewReader(prefix))
		req.ContentLength = int64(len(prefix))
		return capw
	}
	if overflow {
		// Keep orig open: rest still reads the unread tail.
		req.Body = &teeCloser{Reader: io.MultiReader(bytes.NewReader(prefix), rest), c: orig}
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
	} else {
		_ = orig.Close()
		req.Body = io.NopCloser(bytes.NewReader(prefix))
		req.ContentLength = int64(len(prefix))
		req.TransferEncoding = nil
	}
	s.maybeReplaceRequestBody(req, hit, capw, overflow)
	return capw
}

func (s *Server) maybeReplaceRequestBody(req *http.Request, hit *rules.Hit, capw *cappedWriter, overflow bool) {
	replace, ok := rules.BodyReplace(hit)
	if !ok {
		return
	}
	if overflow || int64(len(replace)) > s.maxBody() || int64(len(replace)) > rules.MaxBodyReplace {
		s.metrics.ruleHit(rules.ActionBodySkipped)
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(replace))
	req.ContentLength = int64(len(replace))
	req.TransferEncoding = nil
	req.GetBody = nil
	capw.buf = append([]byte(nil), replace...)
	capw.truncated = false
}

func (s *Server) bufferResponse(resp *http.Response, hit *rules.Hit) *cappedWriter {
	max := s.maxBody()
	capw := &cappedWriter{max: int(max)}
	if resp == nil {
		return capw
	}
	orig := resp.Body
	prefix, overflow, rest, err := readCapped(orig, max)
	capw.buf = append([]byte(nil), prefix...)
	capw.truncated = overflow
	if err != nil {
		if orig != nil {
			_ = orig.Close()
		}
		resp.Body = io.NopCloser(bytes.NewReader(prefix))
		resp.ContentLength = int64(len(prefix))
		return capw
	}
	if overflow {
		resp.Body = &teeCloser{Reader: io.MultiReader(bytes.NewReader(prefix), rest), c: orig}
		resp.ContentLength = -1
	} else {
		if orig != nil {
			_ = orig.Close()
		}
		resp.Body = io.NopCloser(bytes.NewReader(prefix))
		resp.ContentLength = int64(len(prefix))
		resp.TransferEncoding = nil
	}
	replace, ok := rules.BodyReplace(hit)
	if !ok {
		return capw
	}
	if overflow || int64(len(replace)) > max || int64(len(replace)) > rules.MaxBodyReplace {
		s.metrics.ruleHit(rules.ActionBodySkipped)
		return capw
	}
	resp.Body = io.NopCloser(bytes.NewReader(replace))
	resp.ContentLength = int64(len(replace))
	resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(replace)), 10))
	resp.TransferEncoding = nil
	capw.buf = append([]byte(nil), replace...)
	capw.truncated = false
	return capw
}

func (s *Server) teeResponse(resp *http.Response) *cappedWriter {
	if resp == nil {
		return nil
	}
	teed, capw := teeBody(resp.Body, s.maxBody())
	resp.Body = teed
	return capw
}

type bpResult struct {
	id       string
	patch    store.ResumePatch
	dropped  bool
	timedOut bool
	stored   bool
}

func (s *Server) waitBreakpoint(ctx context.Context, f *model.Flow, hit *rules.Hit) bpResult {
	if s.inbox == nil || f == nil || hit == nil {
		s.metrics.ruleHit(rules.ActionBreakpointTO)
		return bpResult{timedOut: true}
	}
	timeout := rules.ClampBreakpointTimeout(hit.Action.Breakpoint.Timeout, s.specNow().Store.MaxWait)
	f.State = model.FlowStatePaused
	f.PausedPhase = hit.Phase
	if f.StartedAt.IsZero() {
		f.StartedAt = time.Now().UTC()
	}
	res, err := s.inbox.Insert(ctx, s.inbox.Epoch(), f)
	if err != nil {
		s.metrics.ruleHit(rules.ActionBreakpointTO)
		return bpResult{timedOut: true}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	patch, err := s.inbox.WaitPaused(wctx, res.ID)
	if err == nil {
		return bpResult{id: res.ID, patch: patch, stored: true}
	}
	if errors.Is(err, store.ErrDropped) {
		return bpResult{id: res.ID, dropped: true, stored: true}
	}
	s.metrics.ruleHit(rules.ActionBreakpointTO)
	return bpResult{id: res.ID, timedOut: true, stored: true}
}

func applyResumePatchRequest(req *http.Request, capw *cappedWriter, patch store.ResumePatch) *cappedWriter {
	if patch.Headers != nil {
		applyPatchToHeader(req.Header, patch.Headers)
	}
	if patch.Body != nil {
		req.Body = io.NopCloser(bytes.NewReader(patch.Body))
		req.ContentLength = int64(len(patch.Body))
		req.TransferEncoding = nil
		return &cappedWriter{buf: append([]byte(nil), patch.Body...), max: len(patch.Body)}
	}
	return capw
}

func applyResumePatchResponse(resp *http.Response, capw *cappedWriter, patch store.ResumePatch) *cappedWriter {
	if patch.Headers != nil {
		applyPatchToHeader(resp.Header, patch.Headers)
	}
	if patch.Body != nil {
		resp.Body = io.NopCloser(bytes.NewReader(patch.Body))
		resp.ContentLength = int64(len(patch.Body))
		resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(patch.Body)), 10))
		resp.TransferEncoding = nil
		return &cappedWriter{buf: append([]byte(nil), patch.Body...), max: len(patch.Body)}
	}
	return capw
}

func (s *Server) syntheticResponse(hit *rules.Hit) *http.Response {
	status := rules.StatusFor(hit)
	if hit != nil && hit.Action.Type == model.ActionBreakpoint {
		status = rules.DefaultSyntheticStatus
	}
	hdr := make(http.Header)
	if hit != nil && hit.Action.Type != model.ActionBreakpoint {
		applyHTTPHeaders(hdr, hit.Action.Headers)
	}
	body, ok := rules.BodyReplace(hit)
	if !ok || hit.Action.Type == model.ActionBreakpoint {
		body = nil
	}
	if len(body) > 0 && hdr.Get("Content-Type") == "" {
		hdr.Set("Content-Type", "text/plain; charset=utf-8")
	}
	hdr.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdr,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func writeClientResponse(w http.ResponseWriter, resp *http.Response) {
	if w == nil || resp == nil {
		return
	}
	httputilx.PrepareResponse(resp.Header, false)
	httputilx.CopyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		drainCopy(w, resp.Body)
	}
}

func writeConnResponse(c net.Conn, resp *http.Response) error {
	if c == nil || resp == nil {
		return nil
	}
	httputilx.PrepareResponse(resp.Header, false)
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1
	if resp.Status == "" {
		resp.Status = strconv.Itoa(resp.StatusCode) + " " + http.StatusText(resp.StatusCode)
	}
	return resp.Write(c)
}

func (s *Server) annotateFlow(f *model.Flow, req *http.Request, reqCap, respCap *cappedWriter, respHdr http.Header, hits ...*rules.Hit) {
	if f == nil {
		return
	}
	if req != nil {
		f.Request.Headers = headersFrom(req.Header)
	}
	if reqCap != nil {
		f.Request.Body = reqCap.buf
		f.Request.Size = len(reqCap.buf)
		f.Request.Truncated = reqCap.truncated
		f.Truncated = f.Truncated || reqCap.truncated
	}
	if respHdr != nil {
		f.Response.Headers = headersFrom(respHdr)
	}
	if respCap != nil {
		f.Response.Body = respCap.buf
		f.Response.Size = len(respCap.buf)
		f.Response.Truncated = respCap.truncated
		f.Truncated = f.Truncated || respCap.truncated
	}
	for _, h := range hits {
		if h != nil && h.ID != "" {
			f.RuleIDs = append(f.RuleIDs, h.ID)
		}
	}
}

func (s *Server) captureRule(f *model.Flow, req *http.Request, reqCap, respCap *cappedWriter, respHdr http.Header, hits ...*rules.Hit) {
	s.annotateFlow(f, req, reqCap, respCap, respHdr, hits...)
	s.capture(f)
}

// runRequestRules applies the request-phase hit. handled means the client
// already received a synthetic response (drop/status/dropped-breakpoint).
func (s *Server) runRequestRules(ctx context.Context, w http.ResponseWriter, req *http.Request, host, scheme string, started time.Time, hit *rules.Hit, reqCap **cappedWriter) (handled bool) {
	return s.runRequestRulesWrite(ctx, req, host, scheme, started, hit, reqCap, func(resp *http.Response) {
		writeClientResponse(w, resp)
	})
}

func (s *Server) runRequestRulesWrite(ctx context.Context, req *http.Request, host, scheme string, started time.Time, hit *rules.Hit, reqCap **cappedWriter, write func(*http.Response)) (handled bool) {
	if hit == nil {
		return false
	}
	switch hit.Action.Type {
	case model.ActionDelay:
		return !s.sleepDelay(ctx, hit.Action.Delay)
	case model.ActionHeader:
		applyHTTPHeaders(req.Header, hit.Action.Headers)
		return false
	case model.ActionBody:
		*reqCap = s.prepareRequestBody(req, hit)
		return false
	case model.ActionDrop, model.ActionStatus:
		*reqCap = s.prepareRequestBody(req, hit)
		syn := s.syntheticResponse(hit)
		write(syn)
		body, _ := rules.BodyReplace(hit)
		respCap := &cappedWriter{buf: body, max: len(body)}
		f := s.flowFromReq(req, host, scheme, syn.StatusCode, "", started)
		s.captureRule(f, req, *reqCap, respCap, syn.Header, hit)
		s.metrics.session("ok")
		return true
	case model.ActionBreakpoint:
		*reqCap = s.prepareRequestBody(req, hit)
		f := s.pausedFlow(req, host, scheme, started, model.RulePhaseRequest, *reqCap, nil, nil, hit)
		bp := s.waitBreakpoint(ctx, f, hit)
		if bp.dropped {
			syn := s.syntheticResponse(hit)
			write(syn)
			s.metrics.session("ok")
			return true
		}
		if !bp.timedOut {
			*reqCap = applyResumePatchRequest(req, *reqCap, bp.patch)
		}
		return false
	default:
		return false
	}
}

func (s *Server) finishHTTPResponse(ctx context.Context, w http.ResponseWriter, req *http.Request, resp *http.Response, host, scheme string, started time.Time, reqHit *rules.Hit, reqCap *cappedWriter, info *model.TLSInfo) {
	s.finishResponseWrite(ctx, req, resp, host, "", scheme, started, reqHit, reqCap, info, func(out *http.Response) error {
		writeClientResponse(w, out)
		return nil
	})
}

func (s *Server) finishConnResponse(ctx context.Context, c net.Conn, req *http.Request, resp *http.Response, host, port, scheme string, started time.Time, reqHit *rules.Hit, reqCap *cappedWriter, info *model.TLSInfo) {
	s.finishResponseWrite(ctx, req, resp, host, port, scheme, started, reqHit, reqCap, info, func(out *http.Response) error {
		return writeConnResponse(c, out)
	})
}

func (s *Server) finishResponseWrite(ctx context.Context, req *http.Request, resp *http.Response, host, port, scheme string, started time.Time, reqHit *rules.Hit, reqCap *cappedWriter, info *model.TLSInfo, write func(*http.Response) error) {
	respHit := s.matchRules(model.RulePhaseResponse, host, req, resp.Header)
	var respCap *cappedWriter
	skipCapture := false
	if respHit != nil {
		switch respHit.Action.Type {
		case model.ActionDelay:
			_ = s.sleepDelay(ctx, respHit.Action.Delay)
		case model.ActionHeader:
			applyHTTPHeaders(resp.Header, respHit.Action.Headers)
		case model.ActionBody:
			respCap = s.bufferResponse(resp, respHit)
		case model.ActionStatus:
			resp.StatusCode = rules.StatusFor(respHit)
			resp.Status = strconv.Itoa(resp.StatusCode) + " " + http.StatusText(resp.StatusCode)
			applyHTTPHeaders(resp.Header, respHit.Action.Headers)
			respCap = s.bufferResponse(resp, respHit)
		case model.ActionDrop:
			respCap = s.bufferResponse(resp, respHit)
			syn := s.syntheticResponse(respHit)
			_ = write(syn)
			f := s.completedFlow(req, host, port, scheme, syn.StatusCode, started, info, reqCap, respCap)
			s.captureRule(f, req, reqCap, respCap, syn.Header, reqHit, respHit)
			s.metrics.session("ok")
			return
		case model.ActionBreakpoint:
			respCap = s.bufferResponse(resp, respHit)
			f := s.pausedFlow(req, host, scheme, started, model.RulePhaseResponse, reqCap, respCap, resp, reqHit, respHit)
			if info != nil {
				f.TLS = info
				f.Intercepted = true
				f.Scheme = scheme
			}
			bp := s.waitBreakpoint(ctx, f, respHit)
			if bp.dropped {
				syn := s.syntheticResponse(respHit)
				_ = write(syn)
				s.metrics.session("ok")
				return
			}
			if !bp.timedOut {
				respCap = applyResumePatchResponse(resp, respCap, bp.patch)
				// Resume already stored the response-phase flow as completed.
				skipCapture = bp.stored
			}
		}
	}
	if respCap == nil {
		respCap = s.teeResponse(resp)
	}
	_ = write(resp)
	if skipCapture {
		s.metrics.session("ok")
		return
	}
	f := s.completedFlow(req, host, port, scheme, resp.StatusCode, started, info, reqCap, respCap)
	s.captureRule(f, req, reqCap, respCap, resp.Header, reqHit, respHit)
	s.metrics.session("ok")
}

func (s *Server) completedFlow(req *http.Request, host, port, scheme string, status int, started time.Time, info *model.TLSInfo, reqCap, respCap *cappedWriter) *model.Flow {
	if info != nil {
		return s.innerFlow(req, host, port, status, "", started, info, reqCap, respCap)
	}
	return s.flowFromReq(req, host, scheme, status, "", started)
}

func (s *Server) pausedFlow(req *http.Request, host, scheme string, started time.Time, phase string, reqCap, respCap *cappedWriter, resp *http.Response, hits ...*rules.Hit) *model.Flow {
	status := 0
	var respHdr http.Header
	if resp != nil {
		status = resp.StatusCode
		respHdr = resp.Header
	}
	u := ""
	if req != nil && req.URL != nil {
		u = req.URL.String()
	}
	f := &model.Flow{
		StartedAt:   started.UTC(),
		State:       model.FlowStatePaused,
		PausedPhase: phase,
		Method:      requestMethod(req),
		URL:         u,
		Host:        host,
		Scheme:      scheme,
		Protocol:    model.FlowProtocolHTTP11,
		Status:      status,
	}
	s.annotateFlow(f, req, reqCap, respCap, respHdr, hits...)
	return f
}
