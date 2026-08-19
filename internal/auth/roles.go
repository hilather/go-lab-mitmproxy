package auth

import "github.com/hilather/go-lab-mitmproxy/internal/model"

// DefaultScopes returns the frozen role → scope set. An explicit token
// Scopes list wins over role expansion.
func DefaultScopes(role string) []string {
	switch role {
	case model.RoleViewer:
		return []string{model.ScopeMITMRead}
	case model.RoleOperator:
		return []string{model.ScopeMITMRead, model.ScopeMITMWrite}
	case model.RoleAdministrator:
		return allScopes()
	default:
		return nil
	}
}

func allScopes() []string {
	return []string{
		model.ScopeMITMRead,
		model.ScopeMITMWrite,
		model.ScopeMITMAdmin,
		model.ScopeMITMAuditRead,
	}
}

func expandScopes(role string, scopes []string) (string, []string) {
	out := append([]string(nil), scopes...)
	if len(out) > 0 {
		if role == "" {
			role = model.RoleAdministrator
		}
		return role, out
	}
	if role == "" {
		role = model.RoleAdministrator
	}
	return role, DefaultScopes(role)
}
