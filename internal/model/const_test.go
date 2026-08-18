package model

import "testing"

func TestAPIIdentity(t *testing.T) {
	if APIVersionV1Alpha1 != "labmitm.dev/v1alpha1" {
		t.Fatalf("apiVersion=%q", APIVersionV1Alpha1)
	}
	if KindLabMITM != "LabMITM" {
		t.Fatalf("kind=%q", KindLabMITM)
	}
	if RevisionPrefix != "sha256:" {
		t.Fatalf("prefix=%q", RevisionPrefix)
	}
}

func TestKnownEnums(t *testing.T) {
	if !KnownScope(ScopeMITMRead) || KnownScope("mail.read") {
		t.Fatal("scope set")
	}
	if !KnownRole(RoleAdministrator) || KnownRole("root") {
		t.Fatal("role set")
	}
	if !KnownOp(OpReplaceStoreCaps) || KnownOp("addZone") {
		t.Fatal("op set")
	}
	if !KnownRulePhase(RulePhaseRequest) || KnownRulePhase("both") {
		t.Fatal("phase set")
	}
	if !KnownRuleAction(ActionBreakpoint) || KnownRuleAction("fuzz") {
		t.Fatal("action set")
	}
}
