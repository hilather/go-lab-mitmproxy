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
	if !KnownOp(OpReplaceStoreCaps) || !KnownOp(OpSetFeature) || !KnownOp(OpReplaceCompat) || KnownOp("addZone") || KnownOp("replaceProtocols") || KnownOp("replaceProxyAccept") {
		t.Fatal("op set")
	}
	if !KnownRulePhase(RulePhaseRequest) || !KnownRulePhase(RulePhaseWebSocket) || KnownRulePhase("both") {
		t.Fatal("phase set")
	}
	if !KnownRuleAction(ActionBreakpoint) || !KnownRuleAction(ActionSilent) || !KnownRuleAction(ActionHang) || !KnownRuleAction(ActionRedirect) || !KnownRuleAction(ActionBlock) || !KnownRuleAction(ActionThrottle) || KnownRuleAction("fuzz") || KnownRuleAction("http_status") {
		t.Fatal("action set")
	}
	if !KnownRuleOpcode(RuleOpcodeText) || KnownRuleOpcode("TEXT") {
		t.Fatal("opcode set")
	}
	if !KnownRuleDirection(WSDirectionClient) || KnownRuleDirection("both") {
		t.Fatal("direction set")
	}
	if !KnownRuleProtocol(FlowProtocolHTTP2) || !KnownRuleProtocol(FlowProtocolSOCKS5) || KnownRuleProtocol("http2") {
		t.Fatal("protocol set")
	}
}
