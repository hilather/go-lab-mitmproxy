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
	default:
		return domainerr.ValidationFailed("unknown operation",
			domainerr.FieldViolation{Path: path + ".op", Code: "invalid_value", Message: "unknown op"})
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
