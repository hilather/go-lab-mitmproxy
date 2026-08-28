package app

import (
	"strconv"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

func applyOperations(st *model.State, ops []model.Operation) error {
	if st == nil {
		return domainerr.ValidationFailed("nil state",
			domainerr.FieldViolation{Path: "", Code: "required", Message: "state is nil"})
	}
	for i, op := range ops {
		if err := applyOne(st, op, i); err != nil {
			return err
		}
	}
	return nil
}

func applyOne(st *model.State, op model.Operation, i int) error {
	path := "operations[" + strconv.Itoa(i) + "]"
	switch op.Op {
	case model.OpReplaceStoreCaps:
		if op.Store == nil {
			return domainerr.ValidationFailed("missing store",
				domainerr.FieldViolation{Path: path + ".store", Code: "required", Message: "replaceStoreCaps requires store"})
		}
		st.Spec.Store.MaxFlows = op.Store.MaxFlows
		st.Spec.Store.MaxBytes = op.Store.MaxBytes
		st.Spec.Store.MaxBodyBytes = op.Store.MaxBodyBytes
		st.Spec.Store.FullPolicy = op.Store.FullPolicy
	case model.OpReplaceAdmission:
		if op.Admission == nil {
			return domainerr.ValidationFailed("missing admission",
				domainerr.FieldViolation{Path: path + ".admission", Code: "required", Message: "replaceAdmission requires admission"})
		}
		st.Spec.Proxy.Admission = *op.Admission
	case model.OpReplaceTLS:
		if op.TLS == nil {
			return domainerr.ValidationFailed("missing tls",
				domainerr.FieldViolation{Path: path + ".tls", Code: "required", Message: "replaceTLS requires tls"})
		}
		st.Spec.TLS = *op.TLS
	case model.OpReplaceRules:
		if op.Rules == nil {
			return domainerr.ValidationFailed("missing rules",
				domainerr.FieldViolation{Path: path + ".rules", Code: "required", Message: "replaceRules requires rules"})
		}
		st.Spec.Rules = *op.Rules
	case model.OpReplaceTargets:
		if op.Targets == nil {
			return domainerr.ValidationFailed("missing targets",
				domainerr.FieldViolation{Path: path + ".targets", Code: "required", Message: "replaceTargets requires targets"})
		}
		st.Spec.Proxy.Targets = *op.Targets
	case model.OpReplaceCompat:
		if op.Compat == nil {
			return domainerr.ValidationFailed("missing compat",
				domainerr.FieldViolation{Path: path + ".compat", Code: "required", Message: "replaceCompat requires compat"})
		}
		st.Spec.Compat = *op.Compat
	case model.OpReplaceHTTPAuth:
		if op.HTTPAuth == nil {
			return domainerr.ValidationFailed("missing httpAuth",
				domainerr.FieldViolation{Path: path + ".httpAuth", Code: "required", Message: "replaceHTTPAuth requires httpAuth"})
		}
		st.Spec.Proxy.HTTPAuth = *op.HTTPAuth
	case model.OpSetFeature:
		if op.Feature == nil {
			return domainerr.ValidationFailed("missing feature",
				domainerr.FieldViolation{Path: path + ".feature", Code: "required", Message: "setFeature requires feature"})
		}
		if err := applySetFeature(&st.Spec, op.Feature, path); err != nil {
			return err
		}
	default:
		return domainerr.ValidationFailed("unknown operation",
			domainerr.FieldViolation{Path: path + ".op", Code: "invalid_value", Message: "unknown op"})
	}
	return nil
}

func applySetFeature(spec *model.Spec, patch *model.FeaturePatch, opPath string) error {
	idPath := opPath + ".feature.id"
	switch patch.ID {
	case FeatureIDHTTP2:
		spec.Protocols.HTTP2.Enabled = patch.Enabled
	case FeatureIDWebSocket:
		spec.Protocols.WebSocket.Enabled = patch.Enabled
	case FeatureIDConnect:
		spec.Protocols.Connect.Enabled = patch.Enabled
	case FeatureIDAbsoluteForm:
		spec.Protocols.AbsoluteForm.Enabled = patch.Enabled
	case FeatureIDAcceptSOCKS5:
		spec.Listeners.Proxy.AcceptSOCKS5 = patch.Enabled
	case FeatureIDAcceptSOCKS4:
		spec.Listeners.Proxy.AcceptSOCKS4 = patch.Enabled
	case FeatureIDCompatFlowREST:
		spec.Compat.FlowREST.Enabled = patch.Enabled
	case FeatureIDRulesEnabled:
		spec.Rules.Enabled = patch.Enabled
	case FeatureIDUIEnabled:
		spec.UI.Enabled = patch.Enabled
	case FeatureIDOriginalDest:
		return domainerr.ValidationFailed("originalDestination is Reset-only",
			domainerr.FieldViolation{Path: idPath, Code: "invalid_value", Message: "listeners.originalDestination is Reset-only"}).
			WithRemediation("edit bootstrap YAML and Reset")
	case FeatureIDTLSIntercept:
		return domainerr.ValidationFailed("tls.intercept is not a setFeature id",
			domainerr.FieldViolation{Path: idPath, Code: "invalid_value", Message: "use replaceTLS to change tls.intercept"}).
			WithRemediation("use replaceTLS")
	default:
		return domainerr.ValidationFailed("unknown feature id",
			domainerr.FieldViolation{Path: idPath, Code: "invalid_value", Message: "unknown feature id"})
	}
	return nil
}

func anyReplaceStoreCaps(ops []model.Operation) bool {
	for i := range ops {
		if ops[i].Op == model.OpReplaceStoreCaps {
			return true
		}
	}
	return false
}

func anyLiveFeatureOp(ops []model.Operation) bool {
	for i := range ops {
		switch ops[i].Op {
		case model.OpSetFeature, model.OpReplaceCompat, model.OpReplaceHTTPAuth:
			return true
		}
	}
	return false
}

func anyReplaceHTTPAuth(ops []model.Operation) bool {
	for i := range ops {
		if ops[i].Op == model.OpReplaceHTTPAuth {
			return true
		}
	}
	return false
}
