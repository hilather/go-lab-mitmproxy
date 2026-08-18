package proxytest

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"
)

type scriptLine struct {
	kind byte // 'C' or 'S'
	text string
}

// PlayTranscript runs a testdata/proxy script against addr.
// vars replaces {{KEY}} tokens in C: and S: lines.
func PlayTranscript(t *testing.T, addr, path string, vars map[string]string) {
	t.Helper()
	script, err := loadTranscript(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	expand := func(s string) string {
		for k, v := range vars {
			s = strings.ReplaceAll(s, "{{"+k+"}}", v)
		}
		return s
	}

	i := 0
	for i < len(script) {
		switch script[i].kind {
		case 'C':
			var raw strings.Builder
			for i < len(script) && script[i].kind == 'C' {
				raw.WriteString(expand(script[i].text))
				raw.WriteString("\r\n")
				i++
			}
			if err := c.WriteRaw([]byte(raw.String())); err != nil {
				t.Fatalf("%s: write: %v", path, err)
			}
		case 'S':
			want := expand(script[i].text)
			i++
			got, err := c.ReadLine()
			if err != nil {
				t.Fatalf("%s: read: %v (want %q)", path, err, want)
			}
			if !matchLine(got, want) {
				t.Fatalf("%s: got %q want %q", path, got, want)
			}
		default:
			t.Fatalf("%s: bad script kind", path)
		}
	}
}

func loadTranscript(path string) ([]scriptLine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []scriptLine
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if len(trim) < 2 || (trim[0] != 'C' && trim[0] != 'S') || trim[1] != ':' {
			return nil, fmt.Errorf("%s:%d: expected C: or S: prefix", path, lineNo)
		}
		text := ""
		if len(trim) > 2 {
			text = strings.TrimSpace(trim[2:])
		}
		out = append(out, scriptLine{kind: trim[0], text: text})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: empty transcript", path)
	}
	return out, nil
}

func matchLine(got, want string) bool {
	if strings.HasSuffix(want, "*") {
		return strings.HasPrefix(got, strings.TrimSuffix(want, "*"))
	}
	return got == want
}
