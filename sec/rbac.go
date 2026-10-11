package sec

import (
	"strings"

	"github.com/cB-Sigma/iotsec"
)

// Permission is a pre-defined permission of TS 60870-5-7 8.2 Table 7.
type Permission uint8

// Permissions of Table 7.
const (
	PermMonitorData Permission = 1 << iota
	PermOperateControls
	PermFileRead
	PermFileWrite
	PermFileMngt
	PermConfigOperation
	PermConfigSecurity
)

// FileCondition is a condition of Table 8 on file permissions (C1 to C5):
// the file types a role may reach.
type FileCondition uint8

// File conditions of Table 8.
const (
	FileOther    FileCondition = 1 << iota // C1: conditional read of other file types
	FileData                               // part of C2
	FileConfig                             // part of C2 and C3
	FileFirmware                           // part of C3
	FileAudit                              // C4
	FileSecurity                           // C5
)

// Role is a pre-defined role of Table 8 (role IDs 0 to 6; 7 to 255 reserved
// for IEC 62351-8, 256 to 32767 for referencing documents and custom roles),
// or an operator defined role of an IEC 62351-8 token (negative IDs).
type Role struct {
	ID    int
	Name  string
	Perms Permission
	Files FileCondition
}

// Roles is Table 8.
var Roles = []Role{
	{0, "VIEWER", PermMonitorData | PermFileRead, FileOther},
	{1, "OPERATOR", PermMonitorData | PermOperateControls | PermFileRead, FileOther},
	{2, "ENGINEER", PermMonitorData | PermFileRead | PermFileWrite | PermFileMngt | PermConfigOperation, FileData | FileConfig},
	{3, "INSTALLER", PermMonitorData | PermFileRead | PermFileWrite | PermConfigOperation, FileConfig | FileFirmware},
	{4, "SECADM", PermFileRead | PermFileWrite | PermFileMngt | PermConfigSecurity, FileSecurity},
	{5, "SECAUD", PermFileRead, FileAudit},
	{6, "RBACMNT", PermFileRead | PermFileWrite | PermFileMngt | PermConfigSecurity, FileSecurity},
}

// RoleByID returns the pre-defined role with the ID.
func RoleByID(id int) (Role, bool) {
	for _, r := range Roles {
		if r.ID == id {
			return r, true
		}
	}
	return Role{}, false
}

// Has reports whether the role grants p. FILEWRITE includes FILEREAD (8.2).
func (r Role) Has(p Permission) bool {
	perms := r.Perms
	if perms&PermFileWrite != 0 {
		perms |= PermFileRead
	}
	return perms&p == p
}

// RequiredPermission is our mapping of a control-direction IEC 101/104 type
// identification to the Table 7 permission it needs. The TS leaves this to
// the implementer (8.3, F-420): process commands and set-points need
// OPERATE CONTROLS; interrogation and read need MONITOR DATA; parameter
// loading and reset process need CONFIG OPERATION PARAMETERS; file calls,
// directory and log queries need FILEREAD and the other file types FILEWRITE;
// clock synchronisation, test, delay acquisition and the security types are
// housekeeping every role may use (0).
func RequiredPermission(typeID uint8) Permission {
	switch {
	case typeID >= 45 && typeID <= 51, typeID >= 58 && typeID <= 64:
		return PermOperateControls
	case typeID == 100 || typeID == 101 || typeID == 102:
		return PermMonitorData
	case typeID == 105, typeID >= 110 && typeID <= 113:
		return PermConfigOperation
	case typeID == 122 || typeID == 126 || typeID == 127:
		return PermFileRead
	case typeID >= 120 && typeID <= 125:
		return PermFileWrite
	default:
		return 0
	}
}

// Authorized reports whether any of the roles may request the type. The
// controlled station answers a refused request with a negative confirmation
// carrying cause 17 (5.4.2.1 Table 1 note), see NotAuthorizedDUI.
func Authorized(roles []Role, typeID uint8) bool {
	p := RequiredPermission(typeID)
	if p == 0 {
		return true
	}
	for _, r := range roles {
		if r.Has(p) {
			return true
		}
	}
	return false
}

// NotAuthorizedDUI returns the DUI of the negative confirmation for a refused
// request: the request's DUI with cause 17 and the P/N bit set.
func NotAuthorizedDUI(req DUI) DUI {
	req.Cause, req.Negative = CauseNotAuthorized, true
	return req
}

var permissionNames = map[string]Permission{
	"MONITORDATA": PermMonitorData, "OPERATECONTROLS": PermOperateControls, "FILEREAD": PermFileRead,
	"FILEWRITE": PermFileWrite, "FILEMNGT": PermFileMngt, "FILEMGT": PermFileMngt,
	"CONFIGOPERATION": PermConfigOperation, "CONFIGOPERATIONPARAMETERS": PermConfigOperation,
	"CONFIGSECURITY": PermConfigSecurity, "CONFIGSECURITYPARAMETERS": PermConfigSecurity,
}

// PermissionByName reads a Table 7 permission name; spaces, hyphens and
// underscores are ignored ("MONITOR DATA", "operate_controls").
func PermissionByName(s string) (Permission, bool) {
	k := strings.ToUpper(strings.NewReplacer(" ", "", "_", "", "-", "").Replace(s))
	p, ok := permissionNames[k]
	return p, ok
}

// RolesFromGrants maps the roles of a verified IEC 62351-8 access token
// (IEC 62351-5:2023 8.3.12.2) to the roles of Table 8: a role of the
// IEC62351-8 role definition is the Table 8 role with its ID; an operator
// defined role grants the Table 7 permissions named in its rights (its
// IEC 62351-8 Table 1 permissions have no IEC 60870-5 meaning). The result
// is never nil: an empty list refuses every request but housekeeping.
func RolesFromGrants(grants []iotsec.RoleGrant) []Role {
	out := []Role{}
	for _, r := range grants {
		if strings.EqualFold(r.Definition, standardDefinition) {
			if x, ok := RoleByID(r.ID); ok {
				out = append(out, x)
			}
			continue
		}
		role := Role{ID: r.ID, Name: r.Name}
		for _, right := range r.Rights {
			if p, ok := PermissionByName(right); ok {
				role.Perms |= p
			}
		}
		out = append(out, role)
	}
	return out
}

// standardDefinition names the role definition of IEC 62351-8 itself.
const standardDefinition = "IEC62351-8"
