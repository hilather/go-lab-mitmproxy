package model

const (
	// APIVersionV1Alpha1 is the only first-GA config API version.
	APIVersionV1Alpha1 = "labmitm.dev/v1alpha1"
	// KindLabMITM is the config document kind.
	KindLabMITM = "LabMITM"
)

// State is the canonical desired-state document.
type State struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       Spec     `json:"spec"`
}

// Metadata is document identity and labels.
type Metadata struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
}

// Spec is the v1alpha1 desired-state contract. YAML decode and default
// materialization live in config, not here.
type Spec struct {
	Listeners     ListenersSpec     `json:"listeners"`
	Proxy         ProxySpec         `json:"proxy"`
	TLS           TLSSpec           `json:"tls"`
	Rules         RulesSpec         `json:"rules"`
	Store         StoreSpec         `json:"store"`
	UI            UISpec            `json:"ui"`
	Management    ManagementSpec    `json:"management"`
	Observability ObservabilitySpec `json:"observability"`
}
