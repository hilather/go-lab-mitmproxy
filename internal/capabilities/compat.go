package capabilities

// DefaultCompatPathPrefix is the default extra REST prefix (D24).
// Paths here use this spelling; the live prefix is configured later.
const DefaultCompatPathPrefix = "/compat"

// CompatBindings is a side table of REST_ONLY extra spellings of existing
// flows.* IDs. catalog(), All(), compileRoutes, and RenderOpenAPI do not
// include these paths.
func CompatBindings() []Capability {
	prefix := DefaultCompatPathPrefix
	out := []Capability{
		{
			ID: FlowsList, Title: "List flows (compat)", Version: VersionTag,
			Description:    "REST_ONLY extra spelling of flows.list. Not compiled onto native routes.",
			RequiredScopes: []string{ScopeMITMRead}, Idempotent: true, RESTOnly: true,
			REST:           []RESTBinding{{Method: "GET", Path: prefix + "/flows"}},
			ServiceMethods: []string{"ListFlows"},
		},
		{
			ID: FlowsGet, Title: "Get flow (compat)", Version: VersionTag,
			Description:    "REST_ONLY extra spelling of flows.get.",
			RequiredScopes: []string{ScopeMITMRead}, Idempotent: true, RESTOnly: true,
			REST:           []RESTBinding{{Method: "GET", Path: prefix + "/flows/{id}"}},
			ServiceMethods: []string{"GetFlow"},
		},
		{
			ID: FlowsDelete, Title: "Delete flow (compat)", Version: VersionTag,
			Description:    "REST_ONLY extra spelling of flows.delete.",
			RequiredScopes: []string{ScopeMITMWrite}, Mutating: true, Idempotent: true, RESTOnly: true,
			REST:           []RESTBinding{{Method: "DELETE", Path: prefix + "/flows/{id}"}},
			ServiceMethods: []string{"DeleteFlow"},
		},
		{
			ID: FlowsClear, Title: "Clear flows (compat)", Version: VersionTag,
			Description:    "REST_ONLY extra spelling of flows.clear.",
			RequiredScopes: []string{ScopeMITMWrite}, Mutating: true, Idempotent: true, RESTOnly: true,
			REST:           []RESTBinding{{Method: "DELETE", Path: prefix + "/flows"}},
			ServiceMethods: []string{"ClearFlows"},
		},
		{
			ID: FlowsReplay, Title: "Replay flow (compat)", Version: VersionTag,
			Description:    "REST_ONLY extra spelling of flows.replay.",
			RequiredScopes: []string{ScopeMITMWrite}, Mutating: true, RESTOnly: true,
			REST:           []RESTBinding{{Method: "POST", Path: prefix + "/flows/{id}/replay"}},
			ServiceMethods: []string{"Replay"},
		},
		{
			ID: FlowsRequest, Title: "Raw request body (compat)", Version: VersionTag,
			Description:    "REST_ONLY extra spelling of flows.request.",
			RequiredScopes: []string{ScopeMITMRead}, Idempotent: true, RESTOnly: true,
			REST:           []RESTBinding{{Method: "GET", Path: prefix + "/flows/{id}/content/request"}},
			ServiceMethods: []string{"GetFlow"},
		},
		{
			ID: FlowsResponse, Title: "Raw response body (compat)", Version: VersionTag,
			Description:    "REST_ONLY extra spelling of flows.response.",
			RequiredScopes: []string{ScopeMITMRead}, Idempotent: true, RESTOnly: true,
			REST:           []RESTBinding{{Method: "GET", Path: prefix + "/flows/{id}/content/response"}},
			ServiceMethods: []string{"GetFlow"},
		},
	}
	cloned := make([]Capability, len(out))
	for i, c := range out {
		cloned[i] = cloneCapability(c)
	}
	return cloned
}
