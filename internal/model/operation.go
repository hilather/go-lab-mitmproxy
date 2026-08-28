package model

// Closed plan/apply verbs. Fine-grained record CRUD is not in 1.0.
const (
	OpReplaceStoreCaps = "replaceStoreCaps"
	OpReplaceAdmission = "replaceAdmission"
	OpReplaceTLS       = "replaceTLS"
	OpReplaceRules     = "replaceRules"
	OpReplaceTargets   = "replaceTargets"
	OpReplaceCompat    = "replaceCompat"
	OpSetFeature       = "setFeature"
	OpReplaceHTTPAuth  = "replaceHTTPAuth"
)

// ChangeSet is the LabDNS-shaped plan/apply envelope.
type ChangeSet struct {
	ExpectedRevision string      `json:"expectedRevision"`
	IdempotencyKey   string      `json:"idempotencyKey"`
	Reason           string      `json:"reason"`
	Force            bool        `json:"force"`
	Operations       []Operation `json:"operations"`
}

// Operation is one typed config mutation.
type Operation struct {
	Op        string         `json:"op"`
	Store     *StoreCaps     `json:"store,omitempty"`
	Admission *AdmissionSpec `json:"admission,omitempty"`
	TLS       *TLSSpec       `json:"tls,omitempty"`
	Rules     *RulesSpec     `json:"rules,omitempty"`
	Targets   *TargetsSpec   `json:"targets,omitempty"`
	Compat    *CompatSpec    `json:"compat,omitempty"`
	Feature   *FeaturePatch  `json:"feature,omitempty"`
	HTTPAuth  *HTTPAuthSpec  `json:"httpAuth,omitempty"`
}

// FeaturePatch is the setFeature body: one closed catalog ID and its bool.
type FeaturePatch struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

// StoreCaps is the replaceStoreCaps body.
type StoreCaps struct {
	MaxFlows     int    `json:"maxFlows"`
	MaxBytes     int64  `json:"maxBytes"`
	MaxBodyBytes int64  `json:"maxBodyBytes"`
	FullPolicy   string `json:"fullPolicy"`
}

// KnownOp reports whether op is a v1alpha1 plan/apply verb.
func KnownOp(op string) bool {
	switch op {
	case OpReplaceStoreCaps, OpReplaceAdmission, OpReplaceTLS, OpReplaceRules, OpReplaceTargets, OpReplaceCompat, OpSetFeature, OpReplaceHTTPAuth:
		return true
	default:
		return false
	}
}

// RevisionStatus is the public revision + store generation view.
type RevisionStatus struct {
	BootstrapRevision Revision   `json:"bootstrapRevision"`
	RuntimeRevision   Revision   `json:"runtimeRevision"`
	Generation        Generation `json:"generation"`
	StoreGeneration   uint64     `json:"storeGeneration"`
	Drifted           bool       `json:"drifted"`
	FlowCount         int        `json:"flowCount"`
	StoreBytes        int64      `json:"storeBytes"`
	LoadedAt          string     `json:"loadedAt"`
}
