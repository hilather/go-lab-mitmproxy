package store

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// ULID (26 Crockford) plus -req.body / -resp.body, optional .tmp.
var spillName = regexp.MustCompile(`(?i)^[0-7][0-9A-HJKMNP-TV-Z]{25}-(req|resp|ws)\.body(\.tmp)?$`)

type spillJob struct {
	reqTmp    string
	reqFinal  string
	respTmp   string
	respFinal string
	wsTmp     string
	wsFinal   string
}

func writeSpillTemps(dir string, threshold int64, f *model.Flow) (*spillJob, error) {
	if dir == "" || threshold <= 0 {
		return nil, nil
	}
	job := &spillJob{}
	if int64(len(f.Request.Body)) >= threshold {
		tmp := filepath.Join(dir, f.ID+"-req.body.tmp")
		if err := os.WriteFile(tmp, f.Request.Body, 0o600); err != nil {
			return nil, fmt.Errorf("%w: request: %v", ErrSpill, err)
		}
		job.reqTmp = tmp
		job.reqFinal = filepath.Join(dir, f.ID+"-req.body")
	}
	if int64(len(f.Response.Body)) >= threshold {
		tmp := filepath.Join(dir, f.ID+"-resp.body.tmp")
		if err := os.WriteFile(tmp, f.Response.Body, 0o600); err != nil {
			unlinkSpillJob(job)
			return nil, fmt.Errorf("%w: response: %v", ErrSpill, err)
		}
		job.respTmp = tmp
		job.respFinal = filepath.Join(dir, f.ID+"-resp.body")
	}
	if blob := wsConcat(f.WebSocket); int64(len(blob)) >= threshold {
		tmp := filepath.Join(dir, f.ID+"-ws.body.tmp")
		if err := os.WriteFile(tmp, blob, 0o600); err != nil {
			unlinkSpillJob(job)
			return nil, fmt.Errorf("%w: websocket: %v", ErrSpill, err)
		}
		job.wsTmp = tmp
		job.wsFinal = filepath.Join(dir, f.ID+"-ws.body")
	}
	if job.reqTmp == "" && job.respTmp == "" && job.wsTmp == "" {
		return nil, nil
	}
	return job, nil
}

func wsConcat(ws *model.WebSocketInfo) []byte {
	if ws == nil {
		return nil
	}
	var n int
	for i := range ws.Frames {
		n += len(ws.Frames[i].Payload)
	}
	if n == 0 {
		return nil
	}
	out := make([]byte, 0, n)
	for i := range ws.Frames {
		out = append(out, ws.Frames[i].Payload...)
	}
	return out
}

func writeSideSpill(dir string, threshold int64, id, side string, body []byte) (string, error) {
	if dir == "" || threshold <= 0 || int64(len(body)) < threshold {
		return "", nil
	}
	tmp := filepath.Join(dir, id+"-"+side+".body.tmp")
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return "", fmt.Errorf("%w: %s: %v", ErrSpill, side, err)
	}
	final := filepath.Join(dir, id+"-"+side+".body")
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("%w: rename %s: %v", ErrSpill, side, err)
	}
	return final, nil
}

func commitSpill(rec *record, job *spillJob) error {
	if job == nil {
		return nil
	}
	if job.reqTmp != "" {
		if err := os.Rename(job.reqTmp, job.reqFinal); err != nil {
			return fmt.Errorf("%w: rename request: %v", ErrSpill, err)
		}
		job.reqTmp = ""
		rec.reqSpill = job.reqFinal
		rec.flow.Request.Body = nil
	}
	if job.respTmp != "" {
		if err := os.Rename(job.respTmp, job.respFinal); err != nil {
			unlinkRecord(rec)
			return fmt.Errorf("%w: rename response: %v", ErrSpill, err)
		}
		job.respTmp = ""
		rec.respSpill = job.respFinal
		rec.flow.Response.Body = nil
	}
	if job.wsTmp != "" {
		if err := os.Rename(job.wsTmp, job.wsFinal); err != nil {
			unlinkRecord(rec)
			return fmt.Errorf("%w: rename websocket: %v", ErrSpill, err)
		}
		job.wsTmp = ""
		rec.wsSpill = job.wsFinal
		clearWSPayloads(rec.flow.WebSocket)
	}
	return nil
}

func clearWSPayloads(ws *model.WebSocketInfo) {
	if ws == nil {
		return
	}
	for i := range ws.Frames {
		if ws.Frames[i].Size == 0 {
			ws.Frames[i].Size = len(ws.Frames[i].Payload)
		}
		ws.Frames[i].Payload = nil
	}
}

func unlinkSpillJob(job *spillJob) {
	if job == nil {
		return
	}
	if job.reqTmp != "" {
		_ = os.Remove(job.reqTmp)
		job.reqTmp = ""
	}
	if job.respTmp != "" {
		_ = os.Remove(job.respTmp)
		job.respTmp = ""
	}
	if job.wsTmp != "" {
		_ = os.Remove(job.wsTmp)
		job.wsTmp = ""
	}
}

func (m *Memory) unlinkAllSpill() error {
	if m.spillDir == "" {
		return nil
	}
	ents, err := os.ReadDir(m.spillDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%w: read dir: %v", ErrSpill, err)
	}
	var first error
	for _, e := range ents {
		if e.IsDir() || !spillName.MatchString(e.Name()) {
			continue
		}
		path := filepath.Join(m.spillDir, e.Name())
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) && first == nil {
			first = fmt.Errorf("%w: unlink %s: %v", ErrSpill, e.Name(), err)
		}
	}
	return first
}

func unlinkRecord(rec *record) {
	if rec == nil {
		return
	}
	if rec.reqSpill != "" {
		_ = os.Remove(rec.reqSpill)
		rec.reqSpill = ""
	}
	if rec.respSpill != "" {
		_ = os.Remove(rec.respSpill)
		rec.respSpill = ""
	}
	if rec.wsSpill != "" {
		_ = os.Remove(rec.wsSpill)
		rec.wsSpill = ""
	}
}

func loadSpill(s recSnap) error {
	// Size==0 after an explicit empty Resume replace must not refill.
	if s.reqSpill != "" && len(s.flow.Request.Body) == 0 && s.flow.Request.Size > 0 {
		b, err := os.ReadFile(s.reqSpill)
		if err != nil {
			return err
		}
		s.flow.Request.Body = b
	}
	if s.respSpill != "" && len(s.flow.Response.Body) == 0 && s.flow.Response.Size > 0 {
		b, err := os.ReadFile(s.respSpill)
		if err != nil {
			return err
		}
		s.flow.Response.Body = b
	}
	if s.wsSpill != "" && s.flow.WebSocket != nil {
		b, err := os.ReadFile(s.wsSpill)
		if err != nil {
			return err
		}
		off := 0
		for i := range s.flow.WebSocket.Frames {
			n := s.flow.WebSocket.Frames[i].Size
			if n == 0 {
				n = len(s.flow.WebSocket.Frames[i].Payload)
			}
			if n == 0 {
				continue
			}
			if off+n > len(b) {
				s.flow.WebSocket.Frames[i].Payload = append([]byte(nil), b[off:]...)
				break
			}
			s.flow.WebSocket.Frames[i].Payload = append([]byte(nil), b[off:off+n]...)
			off += n
		}
	}
	return nil
}

func ensureSpillDir(dir string) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: spill directory: %w", err)
	}
	return nil
}
