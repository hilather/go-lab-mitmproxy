package capabilities

// ID is a frozen capability identifier. Renames are a public-surface change.
type ID string

// First-GA capability IDs. Order matches docs/07-control-plane-and-parity.md.
const (
	HealthLive      ID = "health.live"
	HealthReady     ID = "health.ready"
	VersionGet      ID = "version.get"
	CapabilitiesGet ID = "capabilities.get"
	StatusGet       ID = "status.get"
	SchemaGet       ID = "schema.get"
	StateGet        ID = "state.get"
	StateValidate   ID = "state.validate"
	StateExport     ID = "state.export"
	StateReset      ID = "state.reset"
	ChangesPlan     ID = "changes.plan"
	ChangesApply    ID = "changes.apply"
	SessionCreate   ID = "session.create"
	SessionDelete   ID = "session.delete"
	SessionGet      ID = "session.get"
	EventsStream    ID = "events.stream"
	FlowsList       ID = "flows.list"
	FlowsGet        ID = "flows.get"
	FlowsRequest    ID = "flows.request"
	FlowsResponse   ID = "flows.response"
	FlowsDelete     ID = "flows.delete"
	FlowsClear      ID = "flows.clear"
	FlowsWait       ID = "flows.wait"
	FlowsResume     ID = "flows.resume"
	FlowsDrop       ID = "flows.drop"
	FlowsReplay     ID = "flows.replay"
	CAGet           ID = "ca.get"
	AuditList       ID = "audit.list"
	AuditGet        ID = "audit.get"
	MetricsGet      ID = "metrics.get"
)

// VersionTag is the first-GA capability schema version embedded on every row.
const VersionTag = "v1"
