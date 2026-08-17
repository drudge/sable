package auth

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	PermissionAll           = "*"
	PermissionSettingsRead  = "settings.read"
	PermissionSettingsWrite = "settings.write"
	PermissionZonesRead     = "zones.read"
	PermissionZonesCreate   = "zones.create"
	PermissionZonesSettings = "zones.settings.write"
	PermissionZonesRecords  = "zones.records.write"
	PermissionZonesTransfer = "zones.transfer.manage"
	PermissionZonesDNSSEC   = "zones.dnssec.manage"
	PermissionZonesImport   = "zones.import"
	PermissionZonesExport   = "zones.export"
	PermissionZonesDelete   = "zones.delete"
	PermissionBlockingRead  = "blocking.read"
	PermissionBlockingWrite = "blocking.write"
	PermissionLogsRead      = "logs.read"
	PermissionUsersRead     = "users.read"
	PermissionUsersWrite    = "users.write"
	PermissionClusterRead   = "cluster.read"
	PermissionClusterWrite  = "cluster.write"
	PermissionMetricsRead   = "metrics.read"
	PermissionUpdatesRead   = "updates.read"
	PermissionUpdatesApply  = "updates.apply"
	// A backup carries password hashes, API token hashes, and the key that
	// opens every DNSSEC private key, so taking one is its own permission
	// rather than part of reading settings.
	PermissionBackupCreate  = "backup.create"
	PermissionBackupRestore = "backup.restore"
)

var AllPermissions = []string{
	PermissionSettingsRead, PermissionSettingsWrite,
	PermissionZonesRead, PermissionZonesCreate, PermissionZonesSettings, PermissionZonesRecords,
	PermissionZonesTransfer, PermissionZonesDNSSEC, PermissionZonesImport, PermissionZonesExport, PermissionZonesDelete,
	PermissionBlockingRead, PermissionBlockingWrite,
	PermissionLogsRead, PermissionUsersRead, PermissionUsersWrite,
	PermissionClusterRead, PermissionClusterWrite, PermissionMetricsRead,
	PermissionUpdatesRead, PermissionUpdatesApply,
	PermissionBackupCreate, PermissionBackupRestore,
}

type Surface string

const (
	SurfaceWeb   Surface = "web"
	SurfaceAPI   Surface = "api"
	ResourceZone         = "zone"
	ResourceAll          = "*"
)

type Grant struct {
	Permission   string
	Surface      Surface
	ResourceType string
	ResourceID   string
}

type RoleDefinition struct {
	Name        string
	Description string
	Permissions []string
	Surfaces    []Surface
}

var BuiltInRoles = []RoleDefinition{
	{Name: "Administrator", Description: "Full control of this Sable deployment", Permissions: []string{PermissionAll}},
	{Name: "API Administrator", Description: "Full control through API tokens without Web UI access", Permissions: []string{PermissionAll}, Surfaces: []Surface{SurfaceAPI}},
	{Name: "DNS Administrator", Description: "Manage DNS, policies, logs, and server settings", Permissions: []string{
		PermissionSettingsRead, PermissionSettingsWrite, PermissionZonesRead, PermissionZonesCreate, PermissionZonesSettings,
		PermissionZonesRecords, PermissionZonesTransfer, PermissionZonesDNSSEC, PermissionZonesImport, PermissionZonesExport, PermissionZonesDelete,
		PermissionBlockingRead, PermissionBlockingWrite, PermissionLogsRead,
		PermissionClusterRead, PermissionClusterWrite, PermissionUpdatesRead,
	}},
	{Name: "Operator", Description: "Operate zones and blocking without changing server settings", Permissions: []string{
		PermissionSettingsRead, PermissionZonesRead, PermissionZonesSettings, PermissionZonesRecords, PermissionZonesTransfer, PermissionZonesImport, PermissionZonesExport,
		PermissionBlockingRead, PermissionBlockingWrite, PermissionLogsRead,
		PermissionClusterRead, PermissionUpdatesRead,
	}},
	{Name: "Auditor", Description: "Read-only access to DNS state, settings, and logs", Permissions: []string{
		PermissionSettingsRead, PermissionZonesRead, PermissionBlockingRead, PermissionLogsRead, PermissionClusterRead,
		PermissionUpdatesRead,
	}},
}

type ManagedUser struct {
	ID          int64
	Username    string
	DisplayName string
	Email       string
	Disabled    bool
	Roles       []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Role struct {
	ID          int64
	Name        string
	Description string
	BuiltIn     bool
	Permissions []string
	Grants      []Grant
	Users       int
}

type Session struct {
	HashPrefix string
	UserID     int64
	Username   string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Current    bool
}

type APIToken struct {
	ID         int64
	UserID     int64
	Username   string
	Name       string
	Groups     []string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
}

type AuditRecord struct {
	ID         int64
	OccurredAt time.Time
	Username   string
	Action     string
	ClientIP   string
	Details    string
}

type AdministrationStore interface {
	ListUsers(context.Context) ([]ManagedUser, error)
	ListRoles(context.Context) ([]Role, error)
	ListSessions(context.Context, time.Time) ([]Session, error)
	ListAPITokens(context.Context, time.Time) ([]APIToken, error)
	ListAuditRecords(context.Context, int) ([]AuditRecord, error)
	CreateUser(context.Context, string, string, string, string, []string, time.Time) (ManagedUser, error)
	RolesHaveSurface(context.Context, []string, Surface) (bool, error)
	UpdateUserProfile(context.Context, int64, string, string, string, time.Time) error
	SetUserRoles(context.Context, int64, []string, time.Time) error
	SetUserDisabled(context.Context, int64, bool, time.Time) error
	SetUserPassword(context.Context, int64, string, time.Time) error
	DeleteUser(context.Context, int64) error
	CreateRole(context.Context, string, string, []Grant, time.Time) (Role, error)
	SetRoleGrants(context.Context, int64, []Grant, time.Time) error
	DeleteRole(context.Context, int64) error
	RevokeSession(context.Context, string) error
	DeleteAPIToken(context.Context, int64) error
}

type AdministrationSnapshot struct {
	Users    []ManagedUser
	Roles    []Role
	Sessions []Session
	Tokens   []APIToken
	Audit    []AuditRecord
}

type ProfileSnapshot struct {
	User   ManagedUser
	Roles  []Role
	Tokens []APIToken
}

func (service *Service) Profile(ctx context.Context, principal Principal) (ProfileSnapshot, error) {
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return ProfileSnapshot{}, errors.New("profile store is unavailable")
	}
	users, err := store.ListUsers(ctx)
	if err != nil {
		return ProfileSnapshot{}, err
	}
	var profile ManagedUser
	found := false
	for _, user := range users {
		if user.ID == principal.UserID {
			profile = user
			found = true
			break
		}
	}
	if !found {
		return ProfileSnapshot{}, ErrNotFound
	}
	roles, err := store.ListRoles(ctx)
	if err != nil {
		return ProfileSnapshot{}, err
	}
	assignedRoles := make([]Role, 0, len(profile.Roles))
	for _, role := range roles {
		for _, roleName := range profile.Roles {
			if role.Name == roleName {
				assignedRoles = append(assignedRoles, role)
				break
			}
		}
	}
	tokens, err := store.ListAPITokens(ctx, service.now())
	if err != nil {
		return ProfileSnapshot{}, err
	}
	owned := make([]APIToken, 0, len(tokens))
	for _, token := range tokens {
		if token.UserID == principal.UserID {
			owned = append(owned, token)
		}
	}
	return ProfileSnapshot{User: profile, Roles: assignedRoles, Tokens: owned}, nil
}

func (service *Service) UpdateOwnProfile(ctx context.Context, principal Principal, displayName, email, clientIP, userAgent string) error {
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("profile store is unavailable")
	}
	displayName, email, err := validateUserProfile(principal.Username, displayName, email)
	if err != nil {
		return err
	}
	err = store.UpdateUserProfile(ctx, principal.UserID, principal.Username, displayName, email, service.now())
	if err == nil {
		service.audit(ctx, &principal.UserID, "user.profile.update.self", clientIP, userAgent, "user_id="+formatID(principal.UserID))
	}
	return err
}

func (service *Service) ChangeOwnPassword(ctx context.Context, principal Principal, currentPassword, newPassword, clientIP, userAgent string) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("profile store is unavailable")
	}
	if !service.acquirePasswordOperation() {
		return ErrRateLimited
	}
	defer service.releasePasswordOperation()
	user, err := service.store.UserByUsername(ctx, principal.Username)
	if err != nil || !VerifyPassword(user.PasswordHash, currentPassword) {
		return ErrInvalidCredential
	}
	passwordHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := store.SetUserPassword(ctx, principal.UserID, passwordHash, service.now()); err != nil {
		return err
	}
	service.audit(ctx, &principal.UserID, "user.password.change", clientIP, userAgent, "all sessions revoked")
	return nil
}

func (service *Service) RevokeOwnAPIToken(ctx context.Context, principal Principal, tokenID int64, clientIP, userAgent string) error {
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("profile store is unavailable")
	}
	tokens, err := store.ListAPITokens(ctx, service.now())
	if err != nil {
		return err
	}
	owned := false
	for _, token := range tokens {
		if token.ID == tokenID && token.UserID == principal.UserID {
			owned = true
			break
		}
	}
	if !owned {
		return ErrNotFound
	}
	if err := store.DeleteAPIToken(ctx, tokenID); err != nil {
		return err
	}
	service.audit(ctx, &principal.UserID, "api_token.revoke.self", clientIP, userAgent, "token_id="+formatID(tokenID))
	return nil
}

func (service *Service) Administration(ctx context.Context, principal Principal) (AdministrationSnapshot, error) {
	if err := requirePermission(principal, PermissionUsersRead); err != nil {
		return AdministrationSnapshot{}, err
	}
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return AdministrationSnapshot{}, errors.New("administration store is unavailable")
	}
	now := service.now()
	users, err := store.ListUsers(ctx)
	if err != nil {
		return AdministrationSnapshot{}, err
	}
	roles, err := store.ListRoles(ctx)
	if err != nil {
		return AdministrationSnapshot{}, err
	}
	sessions, err := store.ListSessions(ctx, now)
	if err != nil {
		return AdministrationSnapshot{}, err
	}
	for index := range sessions {
		sessions[index].Current = strings.HasPrefix(principal.SessionHash, sessions[index].HashPrefix)
	}
	tokens, err := store.ListAPITokens(ctx, now)
	if err != nil {
		return AdministrationSnapshot{}, err
	}
	audit, err := store.ListAuditRecords(ctx, 200)
	if err != nil {
		return AdministrationSnapshot{}, err
	}
	return AdministrationSnapshot{Users: users, Roles: roles, Sessions: sessions, Tokens: tokens, Audit: audit}, nil
}

func (service *Service) CreateUser(ctx context.Context, principal Principal, username, displayName, email, password string, roles []string, clientIP, userAgent string) error {
	if err := requirePermission(principal, PermissionUsersWrite); err != nil {
		return err
	}
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("administration store is unavailable")
	}
	normalized, err := normalizeUsername(username)
	if err != nil {
		return err
	}
	displayName, email, err = validateUserProfile(normalized, displayName, email)
	if err != nil {
		return err
	}
	roles = uniqueStrings(roles)
	if len(roles) == 0 {
		return errors.New("at least one role is required")
	}
	webAccess, err := store.RolesHaveSurface(ctx, roles, SurfaceWeb)
	if err != nil {
		return err
	}
	passwordHash := "!"
	if webAccess {
		if err := validatePassword(password); err != nil {
			return fmt.Errorf("password is required for groups with Web UI access: %w", err)
		}
		if !service.acquirePasswordOperation() {
			return ErrRateLimited
		}
		passwordHash, err = HashPassword(password)
		service.releasePasswordOperation()
		if err != nil {
			return err
		}
	}
	_, err = store.CreateUser(ctx, normalized, displayName, email, passwordHash, roles, service.now())
	if err == nil {
		service.audit(ctx, &principal.UserID, "user.create", clientIP, userAgent, "username="+normalized)
	}
	return err
}

func (service *Service) UpdateUserProfile(ctx context.Context, principal Principal, userID int64, username, displayName, email, clientIP, userAgent string) error {
	if err := requirePermission(principal, PermissionUsersWrite); err != nil {
		return err
	}
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("administration store is unavailable")
	}
	normalized, err := normalizeUsername(username)
	if err != nil {
		return err
	}
	displayName, email, err = validateUserProfile(normalized, displayName, email)
	if err != nil {
		return err
	}
	err = store.UpdateUserProfile(ctx, userID, normalized, displayName, email, service.now())
	if err == nil {
		service.audit(ctx, &principal.UserID, "user.profile.update", clientIP, userAgent, "user_id="+formatID(userID))
	}
	return err
}

func (service *Service) SetUserRoles(ctx context.Context, principal Principal, userID int64, roles []string, clientIP, userAgent string) error {
	if err := requirePermission(principal, PermissionUsersWrite); err != nil {
		return err
	}
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("administration store is unavailable")
	}
	if len(roles) == 0 {
		return errors.New("at least one role is required")
	}
	err := store.SetUserRoles(ctx, userID, uniqueStrings(roles), service.now())
	if err == nil {
		service.audit(ctx, &principal.UserID, "user.roles.update", clientIP, userAgent, "user_id="+formatID(userID))
	}
	return err
}

func (service *Service) SetUserDisabled(ctx context.Context, principal Principal, userID int64, disabled bool, clientIP, userAgent string) error {
	if err := requirePermission(principal, PermissionUsersWrite); err != nil {
		return err
	}
	if principal.UserID == userID && disabled {
		return errors.New("you cannot disable your own account")
	}
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("administration store is unavailable")
	}
	err := store.SetUserDisabled(ctx, userID, disabled, service.now())
	if err == nil {
		service.audit(ctx, &principal.UserID, "user.status.update", clientIP, userAgent, "user_id="+formatID(userID))
	}
	return err
}

func (service *Service) SetUserPassword(ctx context.Context, principal Principal, userID int64, password, clientIP, userAgent string) error {
	if err := requirePermission(principal, PermissionUsersWrite); err != nil {
		return err
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("administration store is unavailable")
	}
	if !service.acquirePasswordOperation() {
		return ErrRateLimited
	}
	passwordHash, err := HashPassword(password)
	service.releasePasswordOperation()
	if err != nil {
		return err
	}
	err = store.SetUserPassword(ctx, userID, passwordHash, service.now())
	if err == nil {
		service.audit(ctx, &principal.UserID, "user.password.reset", clientIP, userAgent, "user_id="+formatID(userID))
	}
	return err
}

func (service *Service) DeleteUser(ctx context.Context, principal Principal, userID int64, clientIP, userAgent string) error {
	if err := requirePermission(principal, PermissionUsersWrite); err != nil {
		return err
	}
	if principal.UserID == userID {
		return errors.New("you cannot delete your own account")
	}
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("administration store is unavailable")
	}
	err := store.DeleteUser(ctx, userID)
	if err == nil {
		service.audit(ctx, &principal.UserID, "user.delete", clientIP, userAgent, "user_id="+formatID(userID))
	}
	return err
}

func (service *Service) CreateRole(ctx context.Context, principal Principal, name, description string, grants []Grant, clientIP, userAgent string) error {
	if err := requirePermission(principal, PermissionUsersWrite); err != nil {
		return err
	}
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("administration store is unavailable")
	}
	name = strings.TrimSpace(name)
	if len(name) < 2 || len(name) > 64 {
		return errors.New("role name must contain 2 to 64 characters")
	}
	grants, err := normalizeGrants(grants)
	if err != nil {
		return err
	}
	_, err = store.CreateRole(ctx, name, strings.TrimSpace(description), grants, service.now())
	if err == nil {
		service.audit(ctx, &principal.UserID, "role.create", clientIP, userAgent, "name="+name)
	}
	return err
}

func (service *Service) SetRoleGrants(ctx context.Context, principal Principal, roleID int64, grants []Grant, clientIP, userAgent string) error {
	if err := requirePermission(principal, PermissionUsersWrite); err != nil {
		return err
	}
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("administration store is unavailable")
	}
	grants, err := normalizeGrants(grants)
	if err != nil {
		return err
	}
	err = store.SetRoleGrants(ctx, roleID, grants, service.now())
	if err == nil {
		service.audit(ctx, &principal.UserID, "role.grants.update", clientIP, userAgent, "role_id="+formatID(roleID))
	}
	return err
}

func (service *Service) DeleteRole(ctx context.Context, principal Principal, roleID int64, clientIP, userAgent string) error {
	if err := requirePermission(principal, PermissionUsersWrite); err != nil {
		return err
	}
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("administration store is unavailable")
	}
	err := store.DeleteRole(ctx, roleID)
	if err == nil {
		service.audit(ctx, &principal.UserID, "role.delete", clientIP, userAgent, "role_id="+formatID(roleID))
	}
	return err
}

func (service *Service) RevokeSession(ctx context.Context, principal Principal, hashPrefix, clientIP, userAgent string) error {
	if err := requirePermission(principal, PermissionUsersWrite); err != nil {
		return err
	}
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("administration store is unavailable")
	}
	if hashPrefix == "" {
		return errors.New("session identifier is required")
	}
	err := store.RevokeSession(ctx, hashPrefix)
	if err == nil {
		service.audit(ctx, &principal.UserID, "session.revoke", clientIP, userAgent, "session="+hashPrefix)
	}
	return err
}

func (service *Service) RevokeAPIToken(ctx context.Context, principal Principal, tokenID int64, clientIP, userAgent string) error {
	if err := requirePermission(principal, PermissionUsersWrite); err != nil {
		return err
	}
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return errors.New("administration store is unavailable")
	}
	err := store.DeleteAPIToken(ctx, tokenID)
	if err == nil {
		service.audit(ctx, &principal.UserID, "api_token.revoke", clientIP, userAgent, "token_id="+formatID(tokenID))
	}
	return err
}

func HasPermission(principal Principal, permission string) bool {
	if slices.Contains(principal.Permissions, PermissionAll) || slices.Contains(principal.Permissions, permission) {
		return true
	}
	return slices.ContainsFunc(principal.Grants, func(grant Grant) bool { return grant.Permission == PermissionAll || grant.Permission == permission })
}

func Authorize(principal Principal, permission, resourceType, resourceID string) bool {
	if slices.Contains(principal.Permissions, PermissionAll) {
		return true
	}
	// Tests and callers constructed before resource grants may provide only
	// permissions. Authenticated Sable principals always carry grants; never
	// use the flattened permission list when grants exist because that would
	// erase zone boundaries.
	if len(principal.Grants) == 0 {
		return slices.Contains(principal.Permissions, permission)
	}
	if principal.grantIndex != nil {
		if _, found := principal.grantIndex[grantKey(PermissionAll, "", "")]; found {
			return true
		}
		if resourceType == "" {
			_, found := principal.grantIndex[grantKey(permission, "", "")]
			return found
		}
		if _, found := principal.grantIndex[grantKey(permission, resourceType, resourceID)]; found {
			return true
		}
		_, found := principal.grantIndex[grantKey(permission, resourceType, ResourceAll)]
		return found
	}
	return slices.ContainsFunc(principal.Grants, func(grant Grant) bool {
		if principal.Surface != "" && grant.Surface != principal.Surface {
			return false
		}
		if grant.Permission == PermissionAll {
			return true
		}
		if grant.Permission != permission {
			return false
		}
		if resourceType == "" {
			return grant.ResourceType == ""
		}
		return grant.ResourceType == resourceType && (grant.ResourceID == ResourceAll || grant.ResourceID == resourceID)
	})
}

func grantKey(permission, resourceType, resourceID string) string {
	return permission + "\x00" + resourceType + "\x00" + resourceID
}

func requirePermission(principal Principal, permission string) error {
	if !HasPermission(principal, permission) {
		return ErrForbidden
	}
	return nil
}

func validateUserProfile(username, displayName, email string) (string, string, error) {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		displayName = username
	}
	if len(displayName) > 128 {
		return "", "", errors.New("display name must not exceed 128 characters")
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return displayName, "", nil
	}
	if len(email) > 254 {
		return "", "", errors.New("email address must not exceed 254 characters")
	}
	address, err := mail.ParseAddress(email)
	if err != nil || !strings.EqualFold(address.Address, email) {
		return "", "", errors.New("enter a valid email address")
	}
	return displayName, strings.ToLower(address.Address), nil
}

func normalizeGrants(grants []Grant) ([]Grant, error) {
	allowed := make(map[string]struct{}, len(AllPermissions))
	for _, permission := range AllPermissions {
		allowed[permission] = struct{}{}
	}
	allowed[PermissionAll] = struct{}{}
	result := make([]Grant, 0, len(grants))
	for _, grant := range grants {
		grant.Permission = strings.TrimSpace(grant.Permission)
		grant.ResourceType = strings.TrimSpace(grant.ResourceType)
		grant.ResourceID = strings.TrimSpace(grant.ResourceID)
		if _, found := allowed[grant.Permission]; !found {
			return nil, errors.New("unsupported permission " + grant.Permission)
		}
		if grant.Surface != SurfaceWeb && grant.Surface != SurfaceAPI {
			return nil, errors.New("permission surface must be web or api")
		}
		isZone := strings.HasPrefix(grant.Permission, "zones.") && grant.Permission != PermissionZonesCreate
		if isZone && (grant.ResourceType != ResourceZone || grant.ResourceID == "") {
			return nil, errors.New("zone permission requires a zone scope")
		}
		if !isZone && (grant.ResourceType != "" || grant.ResourceID != "") {
			return nil, errors.New("global permission cannot have a resource scope")
		}
		if !slices.Contains(result, grant) {
			result = append(result, grant)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("at least one permission grant is required")
	}
	return result, nil
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !slices.Contains(result, value) {
			result = append(result, value)
		}
	}
	slices.Sort(result)
	return result
}

func formatID(id int64) string {
	return strconv.FormatInt(id, 10)
}
