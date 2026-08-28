package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestValidateDefaults(t *testing.T) {
	st, err := Load([]byte(mustLoad(t, "valid", "defaults.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(st); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCAFilesRequiresExisting(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: tls\nspec:\n  tls:\n    ca:\n      mode: files\n      certFile: /no/such/cert.pem\n      keyFile: /no/such/key.pem\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationUnresolved)
}

func TestValidateCAFilesResolves(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: tls\nspec:\n  tls:\n    ca:\n      mode: files\n      certFile: " + cert + "\n      keyFile: " + key + "\n"
	st, err := Load([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.TLS.CA.Mode != model.CAModeFiles {
		t.Fatalf("mode=%q", st.Spec.TLS.CA.Mode)
	}
}

func TestValidateGenerateRejectsUnusedKeyFiles(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: tls\nspec:\n  tls:\n    ca:\n      mode: generate\n      certFile: /tmp/x.pem\n      keyFile: /tmp/y.pem\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateEmptyKeyPEM(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: tls\nspec:\n  tls:\n    ca:\n      mode: files\n      certFile: " + cert + "\n      keyFile: " + key + "\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateWorldWritableKey(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0o666); err != nil {
		t.Fatal(err)
	}
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: tls\nspec:\n  tls:\n    ca:\n      mode: files\n      certFile: " + cert + "\n      keyFile: " + key + "\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateMissingAPIVersion(t *testing.T) {
	_, err := Load([]byte(mustLoad(t, "invalid", "missing-apiversion.yaml")))
	_ = requireValidation(t, err, violationRequired)
}

func TestValidateNil(t *testing.T) {
	_ = requireValidation(t, Validate(nil), violationRequired)
}

func TestValidateShortTokenSecret(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("tooshort\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec:\n  management:\n    auth:\n      mode: bearer\n      tokens:\n        - id: admin\n          secretFile: " + tok + "\n          role: administrator\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateStoreCaps(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: s\nspec:\n  store:\n    maxBytes: 512KiB\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateDuplicateRuleID(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: r\nspec:\n  rules:\n    items:\n      - id: same\n        phase: request\n        action:\n          type: drop\n      - id: same\n        phase: request\n        action:\n          type: drop\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationDuplicateID)
}

func TestValidateRuleRequiresPhaseAndAction(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: r\nspec:\n  rules:\n    items:\n      - id: drop-all\n        action:\n          type: drop\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationRequired)

	doc = "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: r\nspec:\n  rules:\n    items:\n      - id: drop-all\n        phase: request\n        action: {}\n"
	_, err = Load([]byte(doc))
	_ = requireValidation(t, err, violationRequired)
}

func TestValidateTokenRequiresRole(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec:\n  management:\n    auth:\n      mode: bearer\n      tokens:\n        - id: admin\n          secretFile: " + tok + "\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationRequired)
}

func TestValidateHostPortOffline(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: h\nspec:\n  listeners:\n    proxy:\n      address: \"does-not-resolve.invalid:8888\"\n"
	st, err := Load([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.Listeners.Proxy.Address != "does-not-resolve.invalid:8888" {
		t.Fatalf("addr=%q", st.Spec.Listeners.Proxy.Address)
	}
}

func TestValidateTokenScopesMaterializeEmpty(t *testing.T) {
	t.Chdir(repoRoot(t))
	st, err := LoadFile(testdata(t, "valid", "rules-and-token.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Spec.Management.Auth.Tokens) != 1 {
		t.Fatalf("tokens=%d", len(st.Spec.Management.Auth.Tokens))
	}
	if st.Spec.Management.Auth.Tokens[0].Scopes == nil {
		t.Fatal("scopes must be empty slice, not nil")
	}
	raw, err := CanonicalJSON(st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"scopes":[]`) {
		t.Fatalf("canonical scopes: %s", raw)
	}
	if !strings.Contains(string(raw), `"X-Attack":"blocked"`) {
		t.Fatalf("missing header set: %s", raw)
	}
}

func TestValidateCompatPathPrefixCollidesWithRESTPath(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  listeners:\n    management:\n      restPath: /custom\n  compat:\n    flowREST:\n      enabled: true\n      pathPrefix: /custom\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateCompatPathPrefixCollidesWithConfiguredMCP(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  listeners:\n    management:\n      mcpPath: /agents\n  compat:\n    flowREST:\n      enabled: true\n      pathPrefix: /agents\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateProtocolFlagDependencies(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		path string
	}{
		{"acceptBind", "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  listeners:\n    proxy:\n      acceptBind: true\n", "spec.listeners.proxy.acceptBind"},
		{"acceptUDPAssociate", "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  listeners:\n    proxy:\n      acceptSOCKS4: true\n      acceptUDPAssociate: true\n", "spec.listeners.proxy.acceptUDPAssociate"},
		{"acceptUserPass-socks5", "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  listeners:\n    proxy:\n      acceptUserPass: true\n", "spec.listeners.proxy.acceptUserPass"},
		{"origin", "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  protocols:\n    http2:\n      origin: true\n", "spec.protocols.http2.origin"},
		{"extendedConnect", "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  protocols:\n    http2:\n      extendedConnect: true\n", "spec.protocols.http2.extendedConnect"},
		{"capturePush", "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  protocols:\n    http2:\n      enabled: true\n      capturePush: true\n", "spec.protocols.http2.capturePush"},
		{"grpcDecode", "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  protocols:\n    http2:\n      grpcDecode: true\n", "spec.protocols.http2.grpcDecode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load([]byte(tc.doc))
			de := requireValidation(t, err, violationInvalidValue)
			found := false
			for _, v := range de.FieldViolations {
				if v.Path == tc.path {
					found = true
				}
			}
			if !found {
				t.Fatalf("want path %q in %+v", tc.path, de.FieldViolations)
			}
		})
	}
}

func TestValidateUserPassEntriesWhenFlagOff(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  listeners:\n    proxy:\n      userPass:\n        users:\n          - id: BadID\n"
	_, err := Load([]byte(doc))
	de := requireValidation(t, err, violationInvalidValue, violationRequired)
	foundID, foundUser, foundPass := false, false, false
	for _, v := range de.FieldViolations {
		switch v.Path {
		case "spec.listeners.proxy.userPass.users[0].id":
			foundID = true
		case "spec.listeners.proxy.userPass.users[0].usernameFile":
			foundUser = true
		case "spec.listeners.proxy.userPass.users[0].passwordFile":
			foundPass = true
		}
	}
	if !foundID || !foundUser || !foundPass {
		t.Fatalf("want id/usernameFile/passwordFile violations, got %+v", de.FieldViolations)
	}
}

func TestValidateUserPassRFC1929Length(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "user")
	pass := filepath.Join(dir, "pass")
	if err := os.WriteFile(user, []byte("labuser\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", 256)
	if err := os.WriteFile(pass, []byte(long+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  listeners:\n    proxy:\n      acceptSOCKS5: true\n      acceptUserPass: true\n      userPass:\n        users:\n          - id: lab-socks\n            usernameFile: " + user + "\n            passwordFile: " + pass + "\n"
	_, err := Load([]byte(doc))
	de := requireValidation(t, err, violationInvalidValue)
	found := false
	for _, v := range de.FieldViolations {
		if v.Path == "spec.listeners.proxy.userPass.users[0].passwordFile" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want passwordFile length violation in %+v", de.FieldViolations)
	}
}

func TestValidateAcceptBindWithSOCKS4Only(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  listeners:\n    proxy:\n      acceptSOCKS4: true\n      acceptBind: true\n"
	st, err := Load([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Spec.Listeners.Proxy.AcceptBind || !st.Spec.Listeners.Proxy.AcceptSOCKS4 || st.Spec.Listeners.Proxy.AcceptSOCKS5 {
		t.Fatalf("proxy=%+v", st.Spec.Listeners.Proxy)
	}
}

func TestValidateExtendedConnectWithClientCleartext(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  protocols:\n    http2:\n      clientCleartext: true\n      extendedConnect: true\n"
	st, err := Load([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.Protocols.HTTP2.Enabled || !st.Spec.Protocols.HTTP2.ClientCleartext || !st.Spec.Protocols.HTTP2.ExtendedConnect {
		t.Fatalf("http2=%+v", st.Spec.Protocols.HTTP2)
	}
}

func TestValidateBlockModesFieldPaths(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		path string
		code string
	}{
		{"http_status", "type: http_status\n          status: 403\n", "spec.rules.items[0].action.type", violationInvalidValue},
		{"hang0", "type: hang\n          hang:\n            timeout: 0s\n", "spec.rules.items[0].action.hang.timeout", violationRequired},
		{"location", "type: redirect\n          redirect:\n            location: \"\"\n", "spec.rules.items[0].action.redirect.location", violationRequired},
		{"redir403", "type: redirect\n          redirect:\n            location: /x\n            status: 403\n", "spec.rules.items[0].action.redirect.status", violationInvalidValue},
		{"close", "type: silent\n          silent:\n            close: reset\n", "spec.rules.items[0].action.silent.close", violationInvalidValue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  rules:\n    items:\n      - id: x\n        phase: request\n        action:\n          " + tc.doc
			_, err := Load([]byte(doc))
			de := requireValidation(t, err, tc.code)
			found := false
			for _, v := range de.FieldViolations {
				if v.Path == tc.path && v.Code == tc.code {
					found = true
				}
			}
			if !found {
				t.Fatalf("want %s %s in %+v", tc.path, tc.code, de.FieldViolations)
			}
		})
	}
}

func TestValidateWebSocketRulePhase(t *testing.T) {
	ok := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: r\nspec:\n  rules:\n    items:\n      - id: drop-text\n        phase: websocket\n        match:\n          opcode: text\n        action:\n          type: drop\n"
	if _, err := Load([]byte(ok)); err != nil {
		t.Fatalf("valid websocket drop: %v", err)
	}
	_, err := Load([]byte("apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: r\nspec:\n  rules:\n    items:\n      - id: bad\n        phase: request\n        action:\n          type: block\n"))
	_ = requireValidation(t, err, violationInvalidValue)
	_, err = Load([]byte("apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: r\nspec:\n  rules:\n    items:\n      - id: bad\n        phase: websocket\n        action:\n          type: body\n"))
	_ = requireValidation(t, err, violationInvalidValue)
	_, err = Load([]byte("apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: r\nspec:\n  rules:\n    items:\n      - id: bad\n        phase: request\n        match:\n          opcode: text\n        action:\n          type: drop\n"))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateUnknownRuleProtocol(t *testing.T) {
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: x\nspec:\n  rules:\n    items:\n      - id: proto\n        phase: request\n        match:\n          protocol: http2\n        action:\n          type: drop\n"
	_, err := Load([]byte(doc))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestValidateUpstreamVerifyFixture(t *testing.T) {
	_, err := Load([]byte(mustLoad(t, "invalid", "upstream-verify.yaml")))
	de := requireValidation(t, err, violationUnknownField)
	found := false
	for _, v := range de.FieldViolations {
		if v.Path == "spec.tls.upstream.verify" || v.Path == "verify" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want verify path in %+v", de.FieldViolations)
	}
}

func TestContainerFixtureIsBearer(t *testing.T) {
	root := repoRoot(t)
	st, err := LoadFile(filepath.Join(root, "testdata", "container", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.Management.Auth.Mode != model.MgmtAuthBearer {
		t.Fatalf("container fixture mode=%q want bearer", st.Spec.Management.Auth.Mode)
	}
	if st.Spec.Management.Auth.Mode == model.MgmtAuthDevLoopbackUnauth {
		t.Fatal("image/default fixtures must not be dev-loopback-unauth")
	}
	if len(st.Spec.Management.Auth.Tokens) == 0 {
		t.Fatal("container fixture must list a token file")
	}
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "container", "token"))
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(raw))
	if len(line) < minTokenSecret {
		t.Fatalf("container token entropy %d want >= %d", len(line), minTokenSecret)
	}
	admin, err := os.ReadFile(filepath.Join(root, "testdata", "config", "valid", "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(admin))) < minTokenSecret {
		t.Fatal("admin.token entropy below 256 bits")
	}
}
