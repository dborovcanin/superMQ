// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/absmach/supermq/groups"
	mggroups "github.com/absmach/supermq/groups"
	mgclients "github.com/absmach/supermq/pkg/clients"
	"github.com/absmach/supermq/pkg/errors"
	repoerr "github.com/absmach/supermq/pkg/errors/repository"
	"github.com/absmach/supermq/pkg/postgres"
	rolesPostgres "github.com/absmach/supermq/pkg/roles/repo/postgres"
	"github.com/jmoiron/sqlx"
)

var _ mggroups.Repository = (*groupRepository)(nil)

const (
	rolesTableNamePrefix = "groups"
	entityTableName      = "groups"
	entityIDColumnName   = "id"
)

var (
	errParentGroupID   = errors.New("parent group id is empty")
	errParentGroupPath = errors.New("parent group path is empty")
	errParentSuffix    = errors.New("parent group path doesn't have parent id suffix")
)

type groupRepository struct {
	db postgres.Database
	rolesPostgres.Repository
}

// New instantiates a PostgreSQL implementation of group
// repository.
func New(db postgres.Database) mggroups.Repository {
	roleRepo := rolesPostgres.NewRepository(db, rolesTableNamePrefix, entityTableName, entityIDColumnName)

	return &groupRepository{
		db:         db,
		Repository: roleRepo,
	}
}

func (repo groupRepository) Save(ctx context.Context, g mggroups.Group) (mggroups.Group, error) {
	q, err := repo.getInsertQuery(ctx, g)
	if err != nil {
		return mggroups.Group{}, errors.Wrap(repoerr.ErrCreateEntity, err)
	}
	dbg, err := toDBGroup(g)
	if err != nil {
		return mggroups.Group{}, err
	}
	row, err := repo.db.NamedQueryContext(ctx, q, dbg)
	if err != nil {
		return mggroups.Group{}, postgres.HandleError(repoerr.ErrCreateEntity, err)
	}

	defer row.Close()
	row.Next()
	dbg = dbGroup{}
	if err := row.StructScan(&dbg); err != nil {
		return mggroups.Group{}, err
	}

	return toGroup(dbg)
}

func (repo groupRepository) Update(ctx context.Context, g mggroups.Group) (mggroups.Group, error) {
	var query []string
	var upq string
	if g.Name != "" {
		query = append(query, "name = :name,")
	}
	if g.Description != "" {
		query = append(query, "description = :description,")
	}
	if g.Metadata != nil {
		query = append(query, "metadata = :metadata,")
	}
	if len(query) > 0 {
		upq = strings.Join(query, " ")
	}
	g.Status = mgclients.EnabledStatus
	q := fmt.Sprintf(`UPDATE groups SET %s updated_at = :updated_at, updated_by = :updated_by
		WHERE id = :id AND status = :status
		RETURNING id, name, description, domain_id, COALESCE(parent_id, '') AS parent_id, metadata, created_at, updated_at, updated_by, status`, upq)

	dbu, err := toDBGroup(g)
	if err != nil {
		return mggroups.Group{}, errors.Wrap(repoerr.ErrUpdateEntity, err)
	}

	row, err := repo.db.NamedQueryContext(ctx, q, dbu)
	if err != nil {
		return mggroups.Group{}, postgres.HandleError(repoerr.ErrUpdateEntity, err)
	}

	defer row.Close()
	if ok := row.Next(); !ok {
		return mggroups.Group{}, errors.Wrap(repoerr.ErrNotFound, row.Err())
	}
	dbu = dbGroup{}
	if err := row.StructScan(&dbu); err != nil {
		return mggroups.Group{}, errors.Wrap(err, repoerr.ErrUpdateEntity)
	}
	return toGroup(dbu)
}

func (repo groupRepository) ChangeStatus(ctx context.Context, group mggroups.Group) (mggroups.Group, error) {
	qc := `UPDATE groups SET status = :status, updated_at = :updated_at, updated_by = :updated_by WHERE id = :id
	RETURNING id, name, description, domain_id, COALESCE(parent_id, '') AS parent_id, metadata, created_at, updated_at, updated_by, status`

	dbg, err := toDBGroup(group)
	if err != nil {
		return mggroups.Group{}, errors.Wrap(repoerr.ErrUpdateEntity, err)
	}
	row, err := repo.db.NamedQueryContext(ctx, qc, dbg)
	if err != nil {
		return mggroups.Group{}, postgres.HandleError(repoerr.ErrUpdateEntity, err)
	}
	defer row.Close()
	if ok := row.Next(); !ok {
		return mggroups.Group{}, errors.Wrap(repoerr.ErrNotFound, row.Err())
	}
	dbg = dbGroup{}
	if err := row.StructScan(&dbg); err != nil {
		return mggroups.Group{}, errors.Wrap(err, repoerr.ErrUpdateEntity)
	}

	return toGroup(dbg)
}

func (repo groupRepository) RetrieveByID(ctx context.Context, id string) (mggroups.Group, error) {
	q := `SELECT id, name, domain_id, COALESCE(parent_id, '') AS parent_id, description, metadata, created_at, updated_at, updated_by, status FROM groups
	    WHERE id = :id`

	dbg := dbGroup{
		ID: id,
	}

	row, err := repo.db.NamedQueryContext(ctx, q, dbg)
	if err != nil {
		return mggroups.Group{}, errors.Wrap(repoerr.ErrViewEntity, err)
	}
	defer row.Close()

	dbg = dbGroup{}
	if row.Next() {
		if err := row.StructScan(&dbg); err != nil {
			return mggroups.Group{}, errors.Wrap(repoerr.ErrNotFound, err)
		}
	}

	return toGroup(dbg)
}

func (repo groupRepository) RetrieveAll(ctx context.Context, pm mggroups.PageMeta) (mggroups.Page, error) {
	var q string
	query := buildQuery(pm)

	q = fmt.Sprintf(`SELECT DISTINCT g.id, g.domain_id, COALESCE(g.parent_id, '') AS parent_id, g.name, g.description,
		g.metadata, g.created_at, g.updated_at, g.updated_by, g.status FROM groups g %s ORDER BY g.created_at LIMIT :limit OFFSET :offset;`, query)

	dbPageMeta, err := toDBGroupPageMeta(pm)
	if err != nil {
		return mggroups.Page{}, errors.Wrap(repoerr.ErrFailedToRetrieveAllGroups, err)
	}
	rows, err := repo.db.NamedQueryContext(ctx, q, dbPageMeta)
	if err != nil {
		return mggroups.Page{}, errors.Wrap(repoerr.ErrFailedToRetrieveAllGroups, err)
	}
	defer rows.Close()

	items, err := repo.processRows(rows)
	if err != nil {
		return mggroups.Page{}, errors.Wrap(repoerr.ErrFailedToRetrieveAllGroups, err)
	}

	cq := fmt.Sprintf(`	SELECT COUNT(*) AS total_count
						FROM (
							SELECT DISTINCT g.id, g.domain_id, COALESCE(g.parent_id, '') AS parent_id, g.name, g.description,
							g.metadata, g.created_at, g.updated_at, g.updated_by, g.status FROM groups g %s
						) AS subquery;
						`, query)

	total, err := postgres.Total(ctx, repo.db, cq, dbPageMeta)
	if err != nil {
		return mggroups.Page{}, errors.Wrap(repoerr.ErrFailedToRetrieveAllGroups, err)
	}

	page := mggroups.Page{PageMeta: pm}
	page.Total = total
	page.Groups = items
	return page, nil
}

func (repo groupRepository) RetrieveByIDs(ctx context.Context, pm mggroups.PageMeta, ids ...string) (mggroups.Page, error) {
	var q string
	if (len(ids) == 0) && (pm.DomainID == "") {
		return mggroups.Page{PageMeta: mggroups.PageMeta{Offset: pm.Offset, Limit: pm.Limit}}, nil
	}
	query := buildQuery(pm, ids...)

	q = fmt.Sprintf(`SELECT DISTINCT g.id, g.domain_id, COALESCE(g.parent_id, '') AS parent_id, g.name, g.description,
		g.metadata, g.created_at, g.updated_at, g.updated_by, g.status FROM groups g %s ORDER BY g.created_at LIMIT :limit OFFSET :offset;`, query)

	dbPageMeta, err := toDBGroupPageMeta(pm)
	if err != nil {
		return mggroups.Page{}, errors.Wrap(repoerr.ErrFailedToRetrieveAllGroups, err)
	}
	rows, err := repo.db.NamedQueryContext(ctx, q, dbPageMeta)
	if err != nil {
		return mggroups.Page{}, errors.Wrap(repoerr.ErrFailedToRetrieveAllGroups, err)
	}
	defer rows.Close()

	items, err := repo.processRows(rows)
	if err != nil {
		return mggroups.Page{}, errors.Wrap(repoerr.ErrFailedToRetrieveAllGroups, err)
	}

	cq := fmt.Sprintf(`	SELECT COUNT(*) AS total_count
						FROM (
							SELECT DISTINCT g.id, g.domain_id, COALESCE(g.parent_id, '') AS parent_id, g.name, g.description,
							g.metadata, g.created_at, g.updated_at, g.updated_by, g.status FROM groups g %s
						) AS subquery;
						`, query)

	total, err := postgres.Total(ctx, repo.db, cq, dbPageMeta)
	if err != nil {
		return mggroups.Page{}, errors.Wrap(repoerr.ErrFailedToRetrieveAllGroups, err)
	}

	page := mggroups.Page{PageMeta: pm}
	page.Total = total
	page.Groups = items
	return page, nil
}

func (repo groupRepository) RetrieveHierarchy(ctx context.Context, id string, hm groups.HierarchyPageMeta) (groups.HierarchyPage, error) {
	query := ""
	switch {
	// ancestors
	case hm.Direction >= 0:
		query = `
		SELECT
			g.id,
			COALESCE(g.parent_id, '') AS parent_id,
			g.domain_id,
			g.name,
			g.description,
			g.metadata,
			g.created_at,
			g.updated_at,
			g.updated_by,
			g.status,
			g.path,
			nlevel(g.path) AS level
		FROM
			groups g
		WHERE
			g.path @> (SELECT path FROM groups WHERE id = :id LIMIT 1);
		`
	// descendants
	case hm.Direction < 0:
		fallthrough
	default:
		query = `
		SELECT
			g.id,
			COALESCE(g.parent_id, '') AS parent_id,
			g.domain_id,
			g.name,
			g.description,
			g.metadata,
			g.created_at,
			g.updated_at,
			g.updated_by,
			g.status,
			g.path,
			nlevel(g.path) AS level
		FROM
			groups g
		WHERE
			g.path <@ (SELECT path FROM groups WHERE id = :id LIMIT 1);
		`
	}
	parameters := map[string]interface{}{
		"id":    id,
		"level": hm.Level,
	}
	rows, err := repo.db.NamedQueryContext(ctx, query, parameters)
	if err != nil {
		return mggroups.HierarchyPage{}, errors.Wrap(repoerr.ErrFailedToRetrieveAllGroups, err)
	}
	defer rows.Close()

	items, err := repo.processRows(rows)
	if err != nil {
		return mggroups.HierarchyPage{}, errors.Wrap(repoerr.ErrFailedToRetrieveAllGroups, err)
	}

	return mggroups.HierarchyPage{HierarchyPageMeta: hm, Groups: items}, nil
}

func (repo groupRepository) AssignParentGroup(ctx context.Context, parentGroupID string, groupIDs ...string) (err error) {
	if len(groupIDs) == 0 {
		return nil
	}

	tx, err := repo.db.BeginTxx(ctx, nil)
	if err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}
	defer func() {
		if err != nil {
			if errRollback := tx.Rollback(); errRollback != nil {
				err = errors.Wrap(err, errRollback)
			}
		}
	}()

	pq := `SELECT id, path FROM groups WHERE id = $1 LIMIT 1;`
	rows, err := tx.Queryx(pq, parentGroupID)
	if err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}
	defer rows.Close()

	pGroups, err := repo.processRows(rows)
	if err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}
	if len(pGroups) == 0 {
		return repoerr.ErrUpdateEntity
	}
	pGroup := pGroups[0]

	if pGroup.ID == "" {
		return errors.Wrap(repoerr.ErrViewEntity, errParentGroupID)
	}
	if pGroup.Path == "" {
		return errors.Wrap(repoerr.ErrViewEntity, errParentGroupPath)
	}
	if !strings.HasSuffix(pGroup.Path, pGroup.ID) {
		return errors.Wrap(repoerr.ErrViewEntity, errParentSuffix)
	}
	sPaths := strings.Split(pGroup.Path, ".") // 021b9f24-5337-469b-abfa-586f5813dd41.bd4a1fea-6303-4dca-9628-301cd1165a8c.c7e8f389-11e9-4849-a474-e186012ddf38
	for _, sPath := range sPaths {
		for _, cgid := range groupIDs {
			if sPath == cgid {
				return errors.Wrap(repoerr.ErrUpdateEntity, fmt.Errorf("cyclic parent, group %s is parent of requested group %s", cgid, parentGroupID))
			}
		}
	}

	query := `	UPDATE groups
			SET parent_id = :parent_id
			WHERE id = ANY(:children_group_ids)
			RETURNING id, path;`

	params := map[string]interface{}{
		"parent_id":          pGroup.ID,
		"children_group_ids": groupIDs,
	}

	crows, err := tx.NamedQuery(query, params)
	if err != nil {
		return postgres.HandleError(repoerr.ErrUpdateEntity, err)
	}
	defer crows.Close()
	cgroups, err := repo.processRows(crows)
	if err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}

	childrenPaths := []string{}
	for _, cg := range cgroups {
		spath := strings.Split(cg.Path, ".")
		if len(spath) > 0 {
			childrenPaths = append(childrenPaths, cg.Path)
		}
	}

	query = `UPDATE groups
				SET path = text2ltree(COALESCE($1, '') || '.' || ltree2text(path))
				WHERE path <@ ANY($2::ltree[]);`

	if _, err := tx.Exec(query, pGroup.Path, childrenPaths); err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}
	return nil
}

// ToDo: Query need to change to ANY
// ToDo: If parent is changed, then path of all children need to be updated https://patshaughnessy.net/2017/12/14/manipulating-trees-using-sql-and-the-postgres-ltree-extension
func (repo groupRepository) UnassignParentGroup(ctx context.Context, parentGroupID string, groupIDs ...string) (err error) {
	if len(groupIDs) == 0 {
		return nil
	}

	tx, err := repo.db.BeginTxx(ctx, nil)
	if err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}
	defer func() {
		if err != nil {
			if errRollback := tx.Rollback(); errRollback != nil {
				err = errors.Wrap(err, errRollback)
			}
		}
	}()
	pq := `SELECT id, path FROM groups WHERE id = $1 LIMIT 1;`
	rows, err := tx.Queryx(pq, parentGroupID)
	if err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}
	defer rows.Close()

	pGroups, err := repo.processRows(rows)
	if err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}
	if len(pGroups) == 0 {
		return repoerr.ErrUpdateEntity
	}
	pGroup := pGroups[0]

	if pGroup.ID == "" {
		return errors.Wrap(repoerr.ErrViewEntity, errParentGroupID)
	}
	if pGroup.Path == "" {
		return errors.Wrap(repoerr.ErrViewEntity, errParentGroupPath)
	}

	query := `UPDATE groups
			  SET parent_id = NULL
			  WHERE id = ANY(:children_group_ids) AND parent_id = :parent_id
			  RETURNING id, path;`

	parameters := map[string]interface{}{
		"parent_id":          pGroup.ID,
		"children_group_ids": groupIDs,
	}
	crows, err := tx.NamedQuery(query, parameters)
	if err != nil {
		return postgres.HandleError(repoerr.ErrUpdateEntity, err)
	}
	defer crows.Close()
	cgroups, err := repo.processRows(crows)
	if err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}

	childrenPaths := []string{}
	for _, cg := range cgroups {
		spath := strings.Split(cg.Path, ".")
		if len(spath) > 0 {
			childrenPaths = append(childrenPaths, cg.Path)
		}
	}

	query = `UPDATE groups
				SET path = text2ltree(replace(ltree2text(path), $1 || '.', ''))
				WHERE path <@ ANY($2::ltree[]);`

	if _, err := tx.Exec(query, pGroup.Path, childrenPaths); err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(repoerr.ErrUpdateEntity, err)
	}
	return nil
}

func (repo groupRepository) UnassignAllChildrenGroup(ctx context.Context, id string) error {
	query := `
			UPDATE groups AS g SET
				parent_id = NULL
			WHERE g.parent = :parent_id ;
	`

	row, err := repo.db.NamedQueryContext(ctx, query, dbGroup{ParentID: &id})
	if err != nil {
		return postgres.HandleError(repoerr.ErrUpdateEntity, err)
	}
	defer row.Close()

	return nil
}

func (repo groupRepository) Delete(ctx context.Context, groupID string) error {
	q := "DELETE FROM groups AS g WHERE g.id = $1;"

	result, err := repo.db.ExecContext(ctx, q, groupID)
	if err != nil {
		return postgres.HandleError(repoerr.ErrRemoveEntity, err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return repoerr.ErrNotFound
	}
	return nil
}

func buildQuery(gm mggroups.PageMeta, ids ...string) string {
	queries := []string{}

	if len(ids) > 0 {
		queries = append(queries, fmt.Sprintf(" id in ('%s') ", strings.Join(ids, "', '")))
	}
	if gm.Name != "" {
		queries = append(queries, "g.name ILIKE '%' || :name || '%'")
	}
	if gm.ID != "" {
		queries = append(queries, "g.id ILIKE '%' || :id || '%'")
	}
	if gm.Status != mgclients.AllStatus {
		queries = append(queries, "g.status = :status")
	}
	if gm.DomainID != "" {
		queries = append(queries, "g.domain_id = :domain_id")
	}
	if len(gm.Metadata) > 0 {
		queries = append(queries, "g.metadata @> :metadata")
	}
	if len(queries) > 0 {
		return fmt.Sprintf("WHERE %s", strings.Join(queries, " AND "))
	}

	return ""
}

type dbGroup struct {
	ID          string           `db:"id"`
	ParentID    *string          `db:"parent_id,omitempty"`
	DomainID    string           `db:"domain_id,omitempty"`
	Name        string           `db:"name"`
	Description string           `db:"description,omitempty"`
	Level       int              `db:"level"`
	Path        string           `db:"path,omitempty"`
	Metadata    []byte           `db:"metadata,omitempty"`
	CreatedAt   time.Time        `db:"created_at"`
	UpdatedAt   sql.NullTime     `db:"updated_at,omitempty"`
	UpdatedBy   *string          `db:"updated_by,omitempty"`
	Status      mgclients.Status `db:"status"`
}

func toDBGroup(g mggroups.Group) (dbGroup, error) {
	data := []byte("{}")
	if len(g.Metadata) > 0 {
		b, err := json.Marshal(g.Metadata)
		if err != nil {
			return dbGroup{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
		data = b
	}
	var parentID *string
	if g.Parent != "" {
		parentID = &g.Parent
	}
	var updatedAt sql.NullTime
	if !g.UpdatedAt.IsZero() {
		updatedAt = sql.NullTime{Time: g.UpdatedAt, Valid: true}
	}
	var updatedBy *string
	if g.UpdatedBy != "" {
		updatedBy = &g.UpdatedBy
	}
	return dbGroup{
		ID:          g.ID,
		Name:        g.Name,
		ParentID:    parentID,
		DomainID:    g.Domain,
		Description: g.Description,
		Metadata:    data,
		Path:        g.Path,
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   updatedAt,
		UpdatedBy:   updatedBy,
		Status:      g.Status,
	}, nil
}

func toGroup(g dbGroup) (mggroups.Group, error) {
	var metadata mgclients.Metadata
	if g.Metadata != nil {
		if err := json.Unmarshal(g.Metadata, &metadata); err != nil {
			return mggroups.Group{}, errors.Wrap(repoerr.ErrMalformedEntity, err)
		}
	}
	var parentID string
	if g.ParentID != nil {
		parentID = *g.ParentID
	}
	var updatedAt time.Time
	if g.UpdatedAt.Valid {
		updatedAt = g.UpdatedAt.Time
	}
	var updatedBy string
	if g.UpdatedBy != nil {
		updatedBy = *g.UpdatedBy
	}

	return mggroups.Group{
		ID:          g.ID,
		Name:        g.Name,
		Parent:      parentID,
		Domain:      g.DomainID,
		Description: g.Description,
		Metadata:    metadata,
		Level:       g.Level,
		Path:        g.Path,
		UpdatedAt:   updatedAt,
		UpdatedBy:   updatedBy,
		CreatedAt:   g.CreatedAt,
		Status:      g.Status,
	}, nil
}

func toDBGroupPageMeta(pm mggroups.PageMeta) (dbGroupPageMeta, error) {
	data := []byte("{}")
	if len(pm.Metadata) > 0 {
		b, err := json.Marshal(pm.Metadata)
		if err != nil {
			return dbGroupPageMeta{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
		data = b
	}
	return dbGroupPageMeta{
		ID:       pm.ID,
		Name:     pm.Name,
		Metadata: data,
		Total:    pm.Total,
		Offset:   pm.Offset,
		Limit:    pm.Limit,
		DomainID: pm.DomainID,
		Status:   pm.Status,
	}, nil
}

// ToDo: check and remove field "Level" after new auth stabilize
type dbGroupPageMeta struct {
	ID       string           `db:"id"`
	Name     string           `db:"name"`
	ParentID string           `db:"parent_id"`
	DomainID string           `db:"domain_id"`
	Metadata []byte           `db:"metadata"`
	Path     string           `db:"path"`
	Level    uint64           `db:"level"`
	Total    uint64           `db:"total"`
	Limit    uint64           `db:"limit"`
	Offset   uint64           `db:"offset"`
	Subject  string           `db:"subject"`
	Action   string           `db:"action"`
	Status   mgclients.Status `db:"status"`
}

func (repo groupRepository) processRows(rows *sqlx.Rows) ([]mggroups.Group, error) {
	var items []mggroups.Group
	for rows.Next() {
		dbg := dbGroup{}
		if err := rows.StructScan(&dbg); err != nil {
			return items, err
		}
		group, err := toGroup(dbg)
		if err != nil {
			return items, err
		}
		items = append(items, group)
	}
	return items, nil
}

func (repo groupRepository) getInsertQuery(c context.Context, g mggroups.Group) (string, error) {
	switch {
	case g.Parent != "":
		parent, err := repo.RetrieveByID(c, g.Parent)
		if err != nil {
			return "", err
		}
		path := parent.Path + "." + g.ID
		if len(strings.Split(path, ".")) > mggroups.MaxPathLength {
			return "", fmt.Errorf("reached max nested depth")
		}
		return fmt.Sprintf(`INSERT INTO groups (name, description, id, domain_id, parent_id, metadata, created_at, status, path)
		VALUES (:name, :description, :id, :domain_id, :parent_id, :metadata, :created_at, :status, '%s')
		RETURNING id, name, description, domain_id, COALESCE(parent_id, '') AS parent_id, metadata, created_at, status, path, nlevel(path) as level;`, path), nil
	default:
		return `INSERT INTO groups (name, description, id, domain_id, metadata, created_at, status, path)
		VALUES (:name, :description, :id, :domain_id, :metadata, :created_at, :status, :id)
		RETURNING id, name, description, domain_id, COALESCE(parent_id, '') AS parent_id, metadata, created_at, status, path, nlevel(path) as level;`, nil
	}
}
