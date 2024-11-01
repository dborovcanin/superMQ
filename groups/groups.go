// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package groups

import (
	"context"
	"time"

	"github.com/absmach/supermq/domains"
	"github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/clients"
	"github.com/absmach/supermq/pkg/roles"
	"github.com/absmach/supermq/pkg/svcutil"
)

// MaxLevel represents the maximum group hierarchy level.
const (
	MaxLevel      = uint64(20)
	MaxPathLength = 20
)

// Group represents the group of Clients.
// Indicates a level in tree hierarchy. Root node is level 1.
// Path in a tree consisting of group IDs
// Paths are unique per domain.
type Group struct {
	ID          string           `json:"id"`
	Domain      string           `json:"domain_id,omitempty"`
	Parent      string           `json:"parent_id,omitempty"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Metadata    clients.Metadata `json:"metadata,omitempty"`
	Level       int              `json:"level,omitempty"`
	Path        string           `json:"path,omitempty"`
	Children    []*Group         `json:"children,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at,omitempty"`
	UpdatedBy   string           `json:"updated_by,omitempty"`
	Status      clients.Status   `json:"status"`
	Permissions []string         `json:"permissions,omitempty"`
}

type Member struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// Memberships contains page related metadata as well as list of memberships that
// belong to this page.
type MembersPage struct {
	Total   uint64   `json:"total"`
	Offset  uint64   `json:"offset"`
	Limit   uint64   `json:"limit"`
	Members []Member `json:"members"`
}

// Page contains page related metadata as well as list
// of Groups that belong to the page.
type Page struct {
	PageMeta
	Groups []Group
}

type HierarchyPageMeta struct {
	Level     uint64 `json:"level"`
	Direction int64  `json:"direction"` // ancestors (+1) or descendants (-1)
	// - `true`  - result is JSON tree representing groups hierarchy,
	// - `false` - result is JSON array of groups.
	// ToDo: Tree is build in API layer now, not in service layer. This need to be fine tuned.
	Tree bool `json:"tree"`
}
type HierarchyPage struct {
	HierarchyPageMeta
	Groups []Group
}

// Repository specifies a group persistence API.
//
//go:generate mockery --name Repository --output=./mocks --filename repository.go --quiet --note "Copyright (c) Abstract Machines" --unroll-variadic=false
type Repository interface {
	// Save group.
	Save(ctx context.Context, g Group) (Group, error)

	// Update a group.
	Update(ctx context.Context, g Group) (Group, error)

	// RetrieveByID retrieves group by its id.
	RetrieveByID(ctx context.Context, id string) (Group, error)

	// RetrieveAll retrieves all groups.
	RetrieveAll(ctx context.Context, pm PageMeta) (Page, error)

	// RetrieveByIDs retrieves group by ids and query.
	RetrieveByIDs(ctx context.Context, pm PageMeta, ids ...string) (Page, error)

	RetrieveHierarchy(ctx context.Context, id string, hm HierarchyPageMeta) (HierarchyPage, error)

	// ChangeStatus changes groups status to active or inactive
	ChangeStatus(ctx context.Context, group Group) (Group, error)

	// AssignParentGroup assigns parent group id to a given group id
	AssignParentGroup(ctx context.Context, parentGroupID string, groupIDs ...string) error

	// UnassignParentGroup unassign parent group id fr given group id
	UnassignParentGroup(ctx context.Context, parentGroupID string, groupIDs ...string) error

	UnassignAllChildrenGroup(ctx context.Context, id string) error

	// Delete a group
	Delete(ctx context.Context, groupID string) error

	roles.Repository
}

//go:generate mockery --name Service --output=./mocks --filename service.go --quiet --note "Copyright (c) Abstract Machines" --unroll-variadic=false
type Service interface {
	// CreateGroup creates new  group.
	CreateGroup(ctx context.Context, session authn.Session, g Group) (Group, error)

	// UpdateGroup updates the group identified by the provided ID.
	UpdateGroup(ctx context.Context, session authn.Session, g Group) (Group, error)

	// ViewGroup retrieves data about the group identified by ID.
	ViewGroup(ctx context.Context, session authn.Session, id string) (Group, error)

	// ListGroups retrieves
	ListGroups(ctx context.Context, session authn.Session, pm PageMeta) (Page, error)

	// EnableGroup logically enables the group identified with the provided ID.
	EnableGroup(ctx context.Context, session authn.Session, id string) (Group, error)

	// DisableGroup logically disables the group identified with the provided ID.
	DisableGroup(ctx context.Context, session authn.Session, id string) (Group, error)

	// DeleteGroup delete the given group id
	DeleteGroup(ctx context.Context, session authn.Session, id string) error

	RetrieveGroupHierarchy(ctx context.Context, session authn.Session, id string, hm HierarchyPageMeta) (HierarchyPage, error)

	AddParentGroup(ctx context.Context, session authn.Session, id, parentID string) error

	RemoveParentGroup(ctx context.Context, session authn.Session, id string) error

	AddChildrenGroups(ctx context.Context, session authn.Session, id string, childrenGroupIDs []string) error

	RemoveChildrenGroups(ctx context.Context, session authn.Session, id string, childrenGroupIDs []string) error

	RemoveAllChildrenGroups(ctx context.Context, session authn.Session, id string) error

	ListChildrenGroups(ctx context.Context, session authn.Session, id string, pm PageMeta) (Page, error)

	roles.RoleManager
}

const (
	OpCreateGroup svcutil.Operation = iota
	OpListGroups
	OpViewGroup
	OpUpdateGroup
	OpEnableGroup
	OpDisableGroup
	OpRetrieveGroupHierarchy
	OpAddParentGroup
	OpRemoveParentGroup
	OpViewParentGroup
	OpAddChildrenGroups
	OpRemoveChildrenGroups
	OpRemoveAllChildrenGroups
	OpListChildrenGroups
	OpAddChannels
	OpRemoveChannels
	OpRemoveAllChannels
	OpListChannels
	OpAddThings
	OpRemoveThings
	OpRemoveAllThings
	OpListThings
	OpDeleteGroup
)

var expectedOperations = []svcutil.Operation{
	OpCreateGroup,
	OpListGroups,
	OpViewGroup,
	OpUpdateGroup,
	OpEnableGroup,
	OpDisableGroup,
	OpRetrieveGroupHierarchy,
	OpAddParentGroup,
	OpRemoveParentGroup,
	OpViewParentGroup,
	OpAddChildrenGroups,
	OpRemoveChildrenGroups,
	OpRemoveAllChildrenGroups,
	OpListChildrenGroups,
	OpAddChannels,
	OpRemoveChannels,
	OpRemoveAllChannels,
	OpListChannels,
	OpAddThings,
	OpRemoveThings,
	OpRemoveAllThings,
	OpListThings,
	OpDeleteGroup,
}

var operationNames = []string{
	"OpCreateGroup",
	"OpListGroups",
	"OpViewGroup",
	"OpUpdateGroup",
	"OpEnableGroup",
	"OpDisableGroup",
	"OpRetrieveGroupHierarchy",
	"OpAddParentGroup",
	"OpRemoveParentGroup",
	"OpViewParentGroup",
	"OpAddChildrenGroups",
	"OpRemoveChildrenGroups",
	"OpRemoveAllChildrenGroups",
	"OpListChildrenGroups",
	"OpAddChannels",
	"OpRemoveChannels",
	"OpRemoveAllChannels",
	"OpListChannels",
	"OpAddThings",
	"OpRemoveThings",
	"OpRemoveAllThings",
	"OpListThings",
	"OpDeleteGroup",
}

func NewOperationPerm() svcutil.OperationPerm {
	return svcutil.NewOperationPerm(expectedOperations, operationNames)
}

// Below codes should moved out of service, may be can be kept in `cmd/<svc>/main.go`
const (
	updatePermission          = "update_permission"
	readPermission            = "read_permission"
	membershipPermission      = "membership_permission"
	deletePermission          = "delete_permission"
	setChildPermission        = "set_child_permission"
	setParentPermission       = "set_parent_permission"
	manageRolePermission      = "manage_role_permission"
	addRoleUsersPermission    = "add_role_users_permission"
	removeRoleUsersPermission = "remove_role_users_permission"
	viewRoleUsersPermission   = "view_role_users_permission"
)

func NewOperationPermissionMap() map[svcutil.Operation]svcutil.Permission {
	opPerm := map[svcutil.Operation]svcutil.Permission{
		OpCreateGroup:             domains.GroupCreatePermission,
		OpListGroups:              readPermission,
		OpViewGroup:               readPermission,
		OpUpdateGroup:             updatePermission,
		OpEnableGroup:             updatePermission,
		OpDisableGroup:            updatePermission,
		OpRetrieveGroupHierarchy:  readPermission,
		OpAddParentGroup:          setParentPermission,
		OpRemoveParentGroup:       setParentPermission,
		OpViewParentGroup:         readPermission,
		OpAddChildrenGroups:       setChildPermission,
		OpRemoveChildrenGroups:    setChildPermission,
		OpRemoveAllChildrenGroups: setChildPermission,
		OpListChildrenGroups:      readPermission,
		OpAddChannels:             "",
		OpRemoveChannels:          "",
		OpRemoveAllChannels:       "",
		OpListChannels:            "",
		OpAddThings:               "",
		OpRemoveThings:            "",
		OpRemoveAllThings:         "",
		OpListThings:              "",
		OpDeleteGroup:             deletePermission,
	}
	return opPerm
}

func NewRolesOperationPermissionMap() map[svcutil.Operation]svcutil.Permission {
	opPerm := map[svcutil.Operation]svcutil.Permission{
		roles.OpAddRole:                manageRolePermission,
		roles.OpRemoveRole:             manageRolePermission,
		roles.OpUpdateRoleName:         manageRolePermission,
		roles.OpRetrieveRole:           manageRolePermission,
		roles.OpRetrieveAllRoles:       manageRolePermission,
		roles.OpRoleAddActions:         manageRolePermission,
		roles.OpRoleListActions:        manageRolePermission,
		roles.OpRoleCheckActionsExists: manageRolePermission,
		roles.OpRoleRemoveActions:      manageRolePermission,
		roles.OpRoleRemoveAllActions:   manageRolePermission,
		roles.OpRoleAddMembers:         addRoleUsersPermission,
		roles.OpRoleListMembers:        viewRoleUsersPermission,
		roles.OpRoleCheckMembersExists: viewRoleUsersPermission,
		roles.OpRoleRemoveMembers:      removeRoleUsersPermission,
		roles.OpRoleRemoveAllMembers:   manageRolePermission,
	}
	return opPerm
}
