package store

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// ULID (26 Crockford) plus -req.body / -resp.body, optional .tmp.
var spillName = regexp.MustCompile(`(?i)^[0-7][0-9A-HJKMNP-TV-Z]{25}-(req|resp)\.body(\.tmp)?$`)

type spillJob struct {
	reqTmp    string
	reqFinal  string
	respTmp   string
	respFinal string
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
	if job.reqTmp == "" && job.respTmp == "" {
		return nil, nil
	}
	return job, nil
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
	return nil
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
