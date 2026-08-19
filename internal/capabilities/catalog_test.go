package capabilities

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
)

func TestCatalogStructure(t *testing.T) {
	if err := ValidateCatalog(); err != nil {
		t.Fatal(err)
	}
	all := All()
	if len(all) != TableRowCount {
		t.Fatalf("len(All())=%d want %d", len(all), TableRowCount)
	}
	if _, ok := Lookup(HealthLive); !ok {
		t.Fatal("Lookup(health.live) missing")
	}
	if _, ok := Lookup(ID("not-a-capability")); ok {
		t.Fatal("Lookup unknown succeeded")
	}
	live := MustLookup(HealthLive)
	if !live.RESTOnly || live.MCP != nil {
		t.Fatalf("health.live must be REST-only: %+v", live)
	}
	ready := MustLookup(HealthReady)
	if !ready.RESTOnly {
		t.Fatal("health.ready must be REST-only")
	}
	if !SessionCapability(SessionCreate) || SessionCapability(FlowsList) {
		t.Fatal("SessionCapability")
	}
}

func TestFrozenIDsStable(t *testing.T) {
	want := []ID{
		HealthLive, HealthReady, VersionGet, CapabilitiesGet, StatusGet, SchemaGet,
		StateGet, StateValidate, StateExport, StateReset, ChangesPlan, ChangesApply,
		SessionCreate, SessionDelete, SessionGet, EventsStream,
		FlowsList, FlowsGet, FlowsRequest, FlowsResponse,
		FlowsDelete, FlowsClear, FlowsWait, FlowsResume, FlowsDrop, FlowsReplay,
		CAGet, AuditList, AuditGet, MetricsGet,
	}
	got := All()
	if len(got) != len(want) {
		t.Fatalf("catalog ids=%d frozen=%d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("row %d id=%q want %q", i, got[i].ID, want[i])
		}
	}
}

func TestLookupRESTAndTool(t *testing.T) {
	c, ok := LookupREST("GET", "/v1/state")
	if !ok || c.ID != StateGet {
		t.Fatalf("LookupREST GET /v1/state = %+v ok=%v", c, ok)
	}
	tools := LookupTool("mitm_change_apply")
	if len(tools) != 1 || tools[0].ID != ChangesApply {
		t.Fatalf("LookupTool apply = %+v", tools)
	}
	if _, ok := LookupResource("labmitm://status"); !ok {
		t.Fatal("missing labmitm://status")
	}
	if _, ok := LookupREST("GET", "/v1/nope"); ok {
		t.Fatal("unexpected REST hit")
	}
	wait, ok := LookupREST("POST", "/v1/flows:wait")
	if !ok || wait.ID != FlowsWait {
		t.Fatalf("wait=%+v ok=%v", wait, ok)
	}
	replay, ok := LookupREST("POST", "/v1/flows/{id}:replay")
	if !ok || replay.ID != FlowsReplay {
		t.Fatalf("replay=%+v ok=%v", replay, ok)
	}
	ca, ok := LookupREST("GET", "/v1/ca")
	if !ok || ca.ID != CAGet {
		t.Fatalf("ca=%+v ok=%v", ca, ok)
	}
}

func TestCatalogRESTPathsAreV1Only(t *testing.T) {
	if len(All()) != TableRowCount {
		t.Fatalf("TableRowCount=%d All=%d", TableRowCount, len(All()))
	}
	for _, c := range All() {
		for _, b := range c.REST {
			if !strings.HasPrefix(b.Path, "/v1") {
				t.Errorf("%s REST path %s is not /v1", c.ID, b.Path)
			}
			if strings.Contains(b.Path, "/compat") {
				t.Errorf("%s catalog REST path must not include /compat: %s", c.ID, b.Path)
			}
		}
	}
}

func TestCompatBindingsSideTable(t *testing.T) {
	binds := CompatBindings()
	if len(binds) == 0 {
		t.Fatal("CompatBindings empty")
	}
	seen := map[string]bool{}
	for _, c := range All() {
		for _, b := range c.REST {
			seen[b.RESTRef()] = true
		}
	}
	for _, c := range binds {
		if c.MCP != nil {
			t.Errorf("%s compat binding must not declare MCP", c.ID)
		}
		if !c.RESTOnly {
			t.Errorf("%s compat binding RESTOnly=false", c.ID)
		}
		for _, b := range c.REST {
			if strings.HasPrefix(b.Path, "/v1") {
				t.Errorf("compat path %s must not be /v1", b.Path)
			}
			if !strings.HasPrefix(b.Path, DefaultCompatPathPrefix+"/") && b.Path != DefaultCompatPathPrefix {
				t.Errorf("compat path %s missing %s prefix", b.Path, DefaultCompatPathPrefix)
			}
			if seen[b.RESTRef()] {
				t.Errorf("compat REST %s leaked into catalog", b.RESTRef())
			}
			if _, ok := LookupREST(b.Method, b.Path); ok {
				t.Errorf("LookupREST(%s %s) hit catalog", b.Method, b.Path)
			}
		}
	}
}

func TestHealthHasNoTools(t *testing.T) {
	for _, id := range []ID{HealthLive, HealthReady, MetricsGet} {
		c := MustLookup(id)
		if !c.RESTOnly {
			t.Errorf("%s RESTOnly=false", id)
		}
		if c.MCP != nil {
			t.Errorf("%s has MCP binding %+v", id, c.MCP)
		}
	}
}

func TestNoSMTPOrEmailOrBasic(t *testing.T) {
	for _, c := range All() {
		for _, b := range c.REST {
			if strings.Contains(b.Path, "/email") || strings.Contains(b.Path, "/relay") || strings.Contains(b.Path, "/smtp") {
				t.Errorf("%s REST path %s", c.ID, b.Path)
			}
		}
		if c.MCP == nil {
			continue
		}
		for _, tname := range c.MCP.Tools {
			if strings.Contains(tname, "mail_") || strings.Contains(tname, "email") {
				t.Errorf("%s tool %s", c.ID, tname)
			}
		}
		for _, r := range c.MCP.Resources {
			if strings.Contains(r, "labmail://") || strings.Contains(r, "email") {
				t.Errorf("%s resource %s", c.ID, r)
			}
		}
	}
}

func TestProblemFromDomainCodes(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   domainerr.Code
		typ    string
	}{
		{domainerr.CursorStale("stale"), 400, domainerr.CodeCursorStale, "urn:labmitm:error:cursor-stale"},
		{domainerr.StoreOverNewCap("over"), 400, domainerr.CodeStoreOverNewCap, "urn:labmitm:error:store-over-new-cap"},
		{domainerr.ValidationFailed("bad"), 400, domainerr.CodeValidationFailed, "urn:labmitm:error:validation-failed"},
		{domainerr.NotFound("gone"), 404, domainerr.CodeNotFound, "urn:labmitm:error:not-found"},
		{domainerr.TargetDenied("no"), 403, domainerr.CodeTargetDenied, "urn:labmitm:error:target-denied"},
		{domainerr.BreakpointInactive("idle"), 409, domainerr.CodeBreakpointInactive, "urn:labmitm:error:breakpoint-inactive"},
		{domainerr.Timeout("wait"), 504, domainerr.CodeTimeout, "urn:labmitm:error:timeout"},
	}
	for _, tc := range cases {
		p := ProblemFrom(tc.err, "urn:labmitm:request:01TEST")
		if p.Status != tc.status || p.Code != tc.code || p.Type != tc.typ {
			t.Fatalf("ProblemFrom(%v)=status=%d code=%s type=%s", tc.err, p.Status, p.Code, p.Type)
		}
		if p.Code == domainerr.CodeValidationFailed && tc.code == domainerr.CodeCursorStale {
			t.Fatal("cursor_stale must not wrap as validation_failed")
		}
	}
}

func TestProblemFromUnknownIsInternal(t *testing.T) {
	p := ProblemFrom(assertErr("boom"), "")
	if p.Code != domainerr.CodeInternalError || p.Detail == "boom" {
		t.Fatalf("unknown error leaked: %+v", p)
	}
}

type assertErr string

func (e assertErr) Error() string { return string(e) }
