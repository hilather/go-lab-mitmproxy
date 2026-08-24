package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func TestPlanApplyReplaceRules(t *testing.T) {
	svc, boot := mustBoot(t)
	ctx := context.Background()
	in := ChangeIn{
		ExpectedRevision: boot.Revision,
		IdempotencyKey:   "rules-1",
		Reason:           "enable capture rules",
		Operations:       []model.Operation{enableRules()},
	}
	plan, err := svc.Plan(ctx, actor(), in)
	if err != nil {
		t.Fatal(err)
	}
	if plan.PreviousRevision != boot.Revision || plan.CandidateRevision == boot.Revision {
		t.Fatalf("plan revs prev=%s cand=%s", plan.PreviousRevision, plan.CandidateRevision)
	}
	if svc.Active().Revision != boot.Revision {
		t.Fatal("plan swapped")
	}
	if svc.Active().CA == nil {
		t.Fatal("bootstrap CA missing")
	}
	oldSPKI := svc.Active().CA.Status().SPKISHA256

	res, err := svc.Apply(ctx, actor(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || !res.Drifted {
		t.Fatalf("applied=%v drifted=%v", res.Applied, res.Drifted)
	}
	if res.RuntimeRevision != plan.CandidateRevision {
		t.Fatalf("apply rev=%s plan=%s", res.RuntimeRevision, plan.CandidateRevision)
	}
	if !svc.Active().Canonical.Spec.Rules.Enabled {
		t.Fatal("rules not enabled")
	}
	if svc.Active().CA == nil || svc.Active().CA.Status().SPKISHA256 != oldSPKI {
		t.Fatal("replaceRules must reuse the CA handle")
	}

	var hooks int
	svc.OnApply(func() { hooks++ })
	again, err := svc.Apply(ctx, actor(), in)
	if err != nil {
		t.Fatal(err)
	}
	if again.Generation != res.Generation {
		t.Fatal("idempotent apply must not swap again")
	}
	if hooks != 0 {
		t.Fatalf("idempotent apply must not fire OnApply, hooks=%d", hooks)
	}

	in.Reason = "different"
	_, err = svc.Apply(ctx, actor(), in)
	requireCode(t, err, domainerr.CodeIdempotencyConflict)
}

func TestApplyRequiresExpectedRevision(t *testing.T) {
	svc, boot := mustBoot(t)
	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		Operations: []model.Operation{enableRules()},
	})
	requireCode(t, err, domainerr.CodeValidationFailed)
	_, err = svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: "sha256:dead",
		Operations:       []model.Operation{enableRules()},
	})
	requireCode(t, err, domainerr.CodeRevisionConflict)
	if svc.Active().Revision != boot.Revision {
		t.Fatal("conflict swapped")
	}
}

func TestReplaceStoreCapsRejectWithoutForce(t *testing.T) {
	svc, boot := mustBoot(t)
	ctx := context.Background()
	insertRaw(t, svc, "one.lab")
	insertRaw(t, svc, "two.lab")
	_, err := svc.Apply(ctx, actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Operations:       []model.Operation{shrinkStore(1, model.FullPolicyReject)},
	})
	requireCode(t, err, domainerr.CodeStoreOverNewCap)
	if svc.Inbox().Stats().FlowCount != 2 {
		t.Fatal("reject shrink evicted")
	}
	if svc.Active().Revision != boot.Revision {
		t.Fatal("failed apply swapped")
	}
}

func TestReplaceStoreCapsForceEvicts(t *testing.T) {
	svc, boot := mustBoot(t)
	ctx := context.Background()
	first := insertRaw(t, svc, "one.lab")
	second := insertRaw(t, svc, "two.lab")
	res, err := svc.Apply(ctx, actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Force:            true,
		Operations:       []model.Operation{shrinkStore(1, model.FullPolicyReject)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied {
		t.Fatal("force apply")
	}
	if svc.Inbox().Stats().FlowCount != 1 {
		t.Fatalf("count=%d", svc.Inbox().Stats().FlowCount)
	}
	if _, err := svc.GetFlow(ctx, actor(), first); err == nil {
		t.Fatal("oldest should be evicted")
	} else {
		requireCode(t, err, domainerr.CodeNotFound)
	}
	if _, err := svc.GetFlow(ctx, actor(), second); err != nil {
		t.Fatalf("newest should remain: %v", err)
	}
	if svc.Active().Canonical.Spec.Store.MaxFlows != 1 {
		t.Fatal("caps not applied")
	}
}

func TestReplaceStoreCapsEvictOldest(t *testing.T) {
	svc, boot := mustBoot(t)
	first := insertRaw(t, svc, "one.lab")
	second := insertRaw(t, svc, "two.lab")
	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Operations:       []model.Operation{shrinkStore(1, model.FullPolicyEvictOldest)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Inbox().Stats().FlowCount != 1 {
		t.Fatalf("count=%d", svc.Inbox().Stats().FlowCount)
	}
	if _, err := svc.GetFlow(context.Background(), actor(), first); err == nil {
		t.Fatal("oldest should be evicted")
	} else {
		requireCode(t, err, domainerr.CodeNotFound)
	}
	if _, err := svc.GetFlow(context.Background(), actor(), second); err != nil {
		t.Fatalf("newest should remain: %v", err)
	}
}

func TestPlanReplaceStoreCapsRejectWithoutForce(t *testing.T) {
	svc, boot := mustBoot(t)
	insertRaw(t, svc, "one.lab")
	insertRaw(t, svc, "two.lab")
	_, err := svc.Plan(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Operations:       []model.Operation{shrinkStore(1, model.FullPolicyReject)},
	})
	requireCode(t, err, domainerr.CodeStoreOverNewCap)
	if svc.Inbox().Stats().FlowCount != 2 {
		t.Fatal("plan must not evict")
	}
	if svc.Active().Revision != boot.Revision {
		t.Fatal("plan swapped")
	}
}

func TestPlanReplaceStoreCapsDoesNotEvict(t *testing.T) {
	svc, boot := mustBoot(t)
	insertRaw(t, svc, "one.lab")
	insertRaw(t, svc, "two.lab")
	plan, err := svc.Plan(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Operations:       []model.Operation{shrinkStore(1, model.FullPolicyEvictOldest)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Inbox().Stats().FlowCount != 2 {
		t.Fatal("plan must not evict")
	}
	saw := false
	for _, w := range plan.Warnings {
		if w.Code == "store_evict" {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("missing store_evict warning: %+v", plan.Warnings)
	}
}

func TestReplaceStoreCapsLastOpWins(t *testing.T) {
	svc, boot := mustBoot(t)
	first := insertRaw(t, svc, "one.lab")
	second := insertRaw(t, svc, "two.lab")
	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Operations: []model.Operation{
			shrinkStore(1, model.FullPolicyReject),
			shrinkStore(1000, model.FullPolicyReject),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Inbox().Stats().FlowCount != 2 {
		t.Fatalf("count=%d", svc.Inbox().Stats().FlowCount)
	}
	if _, err := svc.GetFlow(context.Background(), actor(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetFlow(context.Background(), actor(), second); err != nil {
		t.Fatal(err)
	}
	if svc.Active().Canonical.Spec.Store.MaxFlows != 1000 {
		t.Fatalf("maxFlows=%d", svc.Active().Canonical.Spec.Store.MaxFlows)
	}
}

func TestApplyReplaceTLSRotatesGenerateCA(t *testing.T) {
	svc, boot := mustBoot(t)
	old := svc.Active().CA.Status().SPKISHA256
	tls := boot.Canonical.Spec.TLS
	tls.Intercept = true
	res, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Reason:           "enable intercept",
		Operations:       []model.Operation{{Op: model.OpReplaceTLS, TLS: &tls}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || !svc.Active().Canonical.Spec.TLS.Intercept {
		t.Fatal("replaceTLS")
	}
	if svc.Active().CA.Status().SPKISHA256 == old {
		t.Fatal("replaceTLS must recompile generate-mode CA")
	}
}

func TestApplyReplaceAdmissionAndTargets(t *testing.T) {
	svc, boot := mustBoot(t)
	ad := boot.Canonical.Spec.Proxy.Admission
	ad.MaxSessions = 8
	tg := boot.Canonical.Spec.Proxy.Targets
	tg.AllowHosts = []string{"*.lab"}
	res, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Operations: []model.Operation{
			{Op: model.OpReplaceAdmission, Admission: &ad},
			{Op: model.OpReplaceTargets, Targets: &tg},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied {
		t.Fatal("apply")
	}
	got := svc.Active().Canonical.Spec
	if got.Proxy.Admission.MaxSessions != 8 {
		t.Fatalf("admission=%d", got.Proxy.Admission.MaxSessions)
	}
	if len(got.Proxy.Targets.AllowHosts) != 1 || got.Proxy.Targets.AllowHosts[0] != "*.lab" {
		t.Fatalf("targets=%v", got.Proxy.Targets.AllowHosts)
	}
}

func TestValidateUnknownOp(t *testing.T) {
	svc, _ := mustBoot(t)
	_, err := svc.Validate(context.Background(), actor(), ValidateIn{
		Operations: []model.Operation{{Op: "replaceRelay"}},
	})
	requireCode(t, err, domainerr.CodeValidationFailed)
}

func TestReplaceRulesDoesNotRereadSOCKSPasswordFiles(t *testing.T) {
	dir := t.TempDir()
	uf := filepath.Join(dir, "user")
	pf := filepath.Join(dir, "pass")
	if err := os.WriteFile(uf, []byte("labuser\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pf, []byte("labpass12\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "apiVersion: labmitm.dev/v1alpha1\nkind: LabMITM\nmetadata:\n  name: t\nspec:\n  listeners:\n    proxy:\n      acceptSOCKS5: true\n      acceptUserPass: true\n      userPass:\n        users:\n          - id: lab-socks\n            usernameFile: " + uf + "\n            passwordFile: " + pf + "\n"
	path := filepath.Join(dir, "labmitm.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, err := Boot(context.Background(), Options{BootstrapPath: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	boot := svc.Active()
	if boot == nil || len(boot.SOCKSUsers) != 1 {
		t.Fatalf("SOCKSUsers=%v", boot)
	}
	first := boot.SOCKSUsers[0].Digest
	if err := os.WriteFile(pf, []byte("newpassword1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		IdempotencyKey:   "socks-rules-1",
		Reason:           "enable rules without rereading SOCKS files",
		Operations:       []model.Operation{enableRules()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Active().SOCKSUsers[0].Digest != first {
		t.Fatal("replaceRules must not load new SOCKS password bytes")
	}
	if err := os.Remove(uf); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pf); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: res.RuntimeRevision,
		IdempotencyKey:   "socks-rules-2",
		Reason:           "vanished SOCKS files must not fail replaceRules",
		Operations: []model.Operation{{
			Op: model.OpReplaceRules,
			Rules: &model.RulesSpec{
				Enabled: true,
				Items: []model.RuleSpec{{
					ID:      "drop-x",
					Enabled: true,
					Phase:   model.RulePhaseRequest,
					Match:   model.RuleMatchSpec{PathPrefix: "/x"},
					Action:  model.RuleActionSpec{Type: model.ActionDrop, Status: 403},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatalf("vanished password file failed replaceRules: %v", err)
	}
	if svc.Active().SOCKSUsers[0].Digest != first {
		t.Fatal("vanished file must keep Previous.SOCKSUsers")
	}
	exp, err := svc.Export(context.Background(), actor(), ExportJSON)
	if err != nil {
		t.Fatal(err)
	}
	body := string(exp.Body)
	if strings.Contains(body, "labpass12") || strings.Contains(body, "newpassword1") || strings.Contains(body, "labuser") {
		t.Fatalf("export leaked SOCKS secret: %s", body)
	}
}

func TestExportJSON(t *testing.T) {
	svc, boot := mustBoot(t)
	out, err := svc.Export(context.Background(), actor(), ExportJSON)
	if err != nil {
		t.Fatal(err)
	}
	if out.Revision != boot.Revision || out.Drifted {
		t.Fatalf("export %+v", out)
	}
	if !strings.Contains(string(out.Body), `"apiVersion"`) {
		t.Fatalf("body=%s", out.Body)
	}
	if strings.Contains(string(out.Body), "BEGIN") && strings.Contains(string(out.Body), "PRIVATE") {
		t.Fatal("export leaked a private key")
	}
}

func TestGetStateCopyIsSafe(t *testing.T) {
	svc, _ := mustBoot(t)
	view, err := svc.GetState(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	view.Canonical.Spec.Proxy.Hostname = "mutated"
	if svc.Active().Canonical.Spec.Proxy.Hostname == "mutated" {
		t.Fatal("GetState leaked live pointer")
	}
}

func TestGetCAIsCertOnly(t *testing.T) {
	svc, _ := mustBoot(t)
	pem, err := svc.GetCA(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pem), "BEGIN CERTIFICATE") {
		t.Fatalf("pem=%s", pem)
	}
	if strings.Contains(string(pem), "PRIVATE") {
		t.Fatal("GetCA leaked a private key")
	}
}

func TestStatusIncludesCA(t *testing.T) {
	svc, _ := mustBoot(t)
	st, err := svc.Status(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Ready {
		t.Fatal("store-up app is ready without a listener probe")
	}
	if st.CA.Mode != model.CAModeGenerate || st.CA.SPKISHA256 == "" {
		t.Fatalf("CA %+v", st.CA)
	}
	svc.SetHealth(func() HealthFacts {
		return HealthFacts{ProxyBound: false, StoreUp: true, MgmtBound: true}
	})
	st, err = svc.Status(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	if st.Ready {
		t.Fatal("Status.Ready must follow HealthFacts")
	}
}

func TestApplyReplaceAdmissionMissingBody(t *testing.T) {
	svc, boot := mustBoot(t)
	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Operations:       []model.Operation{{Op: model.OpReplaceAdmission}},
	})
	requireCode(t, err, domainerr.CodeValidationFailed)
}

func TestReplaceRulesDelayValidate(t *testing.T) {
	svc, boot := mustBoot(t)
	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: boot.Revision,
		Operations: []model.Operation{{
			Op: model.OpReplaceRules,
			Rules: &model.RulesSpec{
				Enabled: true,
				Items: []model.RuleSpec{{
					ID:      "too-slow",
					Enabled: true,
					Phase:   model.RulePhaseRequest,
					Action:  model.RuleActionSpec{Type: model.ActionDelay, Delay: 31 * time.Second},
				}},
			},
		}},
	})
	requireCode(t, err, domainerr.CodeValidationFailed)
}
