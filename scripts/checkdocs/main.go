// Command checkdocs verifies required root documents and internal markdown links.
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RequiredRootDocs are the documents FND-001 must find at the repository root.
var RequiredRootDocs = []string{
	"README.md",
	"AGENTS.md",
	"LICENSE",
	"CHANGELOG.md",
	"START-HERE.md",
	"Makefile",
	"go.mod",
	"docs/README.md",
	"docs/01-architecture.md",
	"docs/02-proxy-semantics.md",
	"docs/03-tls-interception.md",
	"docs/04-flow-store.md",
	"docs/05-rules.md",
	"docs/06-state-and-configuration.md",
	"docs/07-control-plane-and-parity.md",
	"docs/08-rest-api.md",
	"docs/09-mcp-api.md",
	"docs/10-security-architecture.md",
	"docs/11-observability.md",
	"docs/12-testing-strategy.md",
	"docs/13-deployment.md",
	"docs/14-integration-lab.md",
	"docs/known-limitations.md",
	"docs/releases/v1.0.0-rc.1.md",
	"docs/adr/0001-use-go.md",
	"docs/adr/0002-in-tree-http-forward-proxy.md",
	"docs/adr/0003-ephemeral-flows-and-gitops.md",
	"docs/adr/0004-shared-capability-registry.md",
	"docs/adr/0005-lab-static-bearer.md",
	"docs/adr/0006-pin-mcp-protocol-versions.md",
	"docs/adr/0007-no-mitmproxy-compat-surface.md",
	"tasks/00-program-board.md",
	"tasks/README.md",
	".github/workflows/ci.yml",
	".github/workflows/release.yml",
}

var mdLink = regexp.MustCompile(`\[[^\]]*\]\(([^)]+)\)`)

func main() {
	root, err := repoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkdocs: %v\n", err)
		os.Exit(1)
	}
	if err := Check(root); err != nil {
		fmt.Fprintf(os.Stderr, "checkdocs: %v\n", err)
		os.Exit(1)
	}
}

// Check verifies required documents exist and markdown internal links resolve.
func Check(root string) error {
	var missing []string
	for _, rel := range RequiredRootDocs {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			missing = append(missing, rel)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required documents missing: %s", strings.Join(missing, ", "))
	}

	var broken []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "testdata" || base == "vendor" || base == "node_modules" || base == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".md") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		// Frozen regexes and YAML look like markdown links; only scan prose.
		prose := stripCode(body)
		for _, m := range mdLink.FindAllSubmatch(prose, -1) {
			target := strings.TrimSpace(string(m[1]))
			if i := strings.IndexAny(target, " \t"); i >= 0 {
				target = target[:i]
			}
			if skipLink(target) {
				continue
			}
			target = strings.SplitN(target, "#", 2)[0]
			if target == "" {
				continue
			}
			resolved := filepath.Join(filepath.Dir(path), filepath.FromSlash(target))
			if _, err := os.Stat(resolved); err != nil {
				broken = append(broken, fmt.Sprintf("%s -> %s", rel, target))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(broken) > 0 {
		return fmt.Errorf("broken markdown links:\n  %s", strings.Join(broken, "\n  "))
	}
	if err := checkMetadata(root); err != nil {
		return err
	}
	// Fixture trees used by checkdocs tests have no fuzz packages.
	if _, err := os.Stat(filepath.Join(root, "internal", "config", "fuzz_test.go")); err == nil {
		if err := checkFuzzCorpora(root); err != nil {
			return err
		}
	}
	return checkExampleYAML(root)
}

// RequiredFuzzCorpora are the GA-001 seed directories. Deleting them must
// fail closed; in-function f.Add seeds are not a substitute.
var RequiredFuzzCorpora = []string{
	"internal/buildinfo/testdata/fuzz/FuzzInfoString",
	"internal/config/testdata/fuzz/FuzzDecode",
	"internal/httputilx/testdata/fuzz/FuzzReadRequest",
}

func checkFuzzCorpora(root string) error {
	var missing []string
	for _, rel := range RequiredFuzzCorpora {
		dir := filepath.Join(root, filepath.FromSlash(rel))
		ents, err := os.ReadDir(dir)
		if err != nil {
			missing = append(missing, rel+": "+err.Error())
			continue
		}
		ok := false
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			body, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			if bytes.HasPrefix(body, []byte("go test fuzz v1")) {
				ok = true
				break
			}
		}
		if !ok {
			missing = append(missing, rel+": no seed starting with go test fuzz v1")
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("fuzz corpora missing:\n  %s", strings.Join(missing, "\n  "))
	}
	return nil
}

var numberedDoc = regexp.MustCompile(`^docs/[0-9]{2}-.+\.md$`)

func checkMetadata(root string) error {
	var missing []string
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "adr" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !numberedDoc.MatchString(rel) {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(body)
		if !hasMeta(text, "Status:") {
			missing = append(missing, rel+": Status")
		}
		if !hasMeta(text, "Last reviewed:") {
			missing = append(missing, rel+": Last reviewed")
		}
		if !strings.Contains(text, "Status: Informational") && !hasMeta(text, "Owners:") {
			missing = append(missing, rel+": Owners")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("documentation metadata missing:\n  %s", strings.Join(missing, "\n  "))
	}
	return nil
}

func hasMeta(text, key string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), key) {
			return true
		}
	}
	return false
}

func checkExampleYAML(root string) error {
	var broken []string
	roots := []string{
		filepath.Join(root, "examples"),
	}
	for _, dir := range roots {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := yamlLooksStructured(body); err != nil {
				rel, _ := filepath.Rel(root, path)
				broken = append(broken, fmt.Sprintf("%s: %v", rel, err))
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if len(broken) > 0 {
		return fmt.Errorf("invalid example YAML:\n  %s", strings.Join(broken, "\n  "))
	}
	return nil
}

// yamlLooksStructured rejects empty files and tabs-as-indent, which have
// already caused operator-facing compose examples to fail closed.
func yamlLooksStructured(body []byte) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return fmt.Errorf("empty file")
	}
	for i, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "\t") {
			return fmt.Errorf("line %d uses a tab indent", i+1)
		}
	}
	return nil
}

var (
	fencedCode = regexp.MustCompile("(?s)```.*?```")
	inlineCode = regexp.MustCompile("`[^`]*`")
)

func stripCode(body []byte) []byte {
	out := fencedCode.ReplaceAll(body, nil)
	return inlineCode.ReplaceAll(out, nil)
}

func skipLink(target string) bool {
	switch {
	case target == "":
		return true
	case strings.HasPrefix(target, "#"):
		return true
	case strings.HasPrefix(target, "http://"), strings.HasPrefix(target, "https://"), strings.HasPrefix(target, "mailto:"):
		return true
	default:
		return false
	}
}

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s", wd)
		}
		dir = parent
	}
}
