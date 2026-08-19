package compat

// RESTRef keys match capabilities.CompatBindings() spellings (default prefix).
// rest.Server rewrites a live pathPrefix onto these routes before dispatch.
const (
	RefList            = "GET /compat/flows"
	RefGet             = "GET /compat/flows/{id}"
	RefDelete          = "DELETE /compat/flows/{id}"
	RefClear           = "DELETE /compat/flows"
	RefReplay          = "POST /compat/flows/{id}/replay"
	RefRequestContent  = "GET /compat/flows/{id}/content/request"
	RefResponseContent = "GET /compat/flows/{id}/content/response"

	// ListLimit is D52: newest 200, then X-LabMITM-Truncated.
	ListLimit = 200
)
