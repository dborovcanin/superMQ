// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	mggroups "github.com/absmach/supermq/groups"
	"github.com/absmach/supermq/internal/api"
	"github.com/absmach/supermq/pkg/apiutil"
	mgclients "github.com/absmach/supermq/pkg/clients"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/go-chi/chi/v5"
)

func DecodeGroupCreate(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), api.ContentType) {
		return nil, errors.Wrap(apiutil.ErrValidation, apiutil.ErrUnsupportedContentType)
	}
	var g mggroups.Group
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	req := createGroupReq{
		Group: g,
	}

	return req, nil
}

func DecodeListGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	pm, err := decodePageMeta(r)
	if err != nil {
		return nil, err
	}

	req := listGroupsReq{
		PageMeta: pm,
	}
	return req, nil
}

func DecodeGroupUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), api.ContentType) {
		return nil, errors.Wrap(apiutil.ErrValidation, apiutil.ErrUnsupportedContentType)
	}
	req := updateGroupReq{
		id: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func DecodeGroupRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := groupReq{
		id: chi.URLParam(r, "groupID"),
	}
	return req, nil
}

func DecodeChangeGroupStatusRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := changeGroupStatusReq{
		id: chi.URLParam(r, "groupID"),
	}
	return req, nil
}

func decodeRetrieveGroupHierarchy(_ context.Context, r *http.Request) (interface{}, error) {
	hm, err := decodeHierarchyPageMeta(r)
	if err != nil {
		return nil, err
	}

	req := retrieveGroupHierarchyReq{
		id:                chi.URLParam(r, "groupID"),
		HierarchyPageMeta: hm,
	}
	return req, nil
}

func decodeAddParentGroupRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), api.ContentType) {
		return nil, errors.Wrap(apiutil.ErrValidation, apiutil.ErrUnsupportedContentType)
	}

	req := addParentGroupReq{
		id: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func decodeRemoveParentGroupRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := removeParentGroupReq{
		id: chi.URLParam(r, "groupID"),
	}
	return req, nil
}

func decodeAddChildrenGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), api.ContentType) {
		return nil, errors.Wrap(apiutil.ErrValidation, apiutil.ErrUnsupportedContentType)
	}
	req := addChildrenGroupsReq{
		id: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func decodeRemoveChildrenGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), api.ContentType) {
		return nil, errors.Wrap(apiutil.ErrValidation, apiutil.ErrUnsupportedContentType)
	}
	req := removeChildrenGroupsReq{
		id: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func decodeRemoveAllChildrenGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := removeAllChildrenGroupsReq{
		id: chi.URLParam(r, "groupID"),
	}
	return req, nil
}

func decodeListChildrenGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	pm, err := decodePageMeta(r)
	if err != nil {
		return nil, err
	}

	req := listChildrenGroupsReq{
		id:       chi.URLParam(r, "groupID"),
		PageMeta: pm,
	}
	return req, nil
}

func decodeHierarchyPageMeta(r *http.Request) (mggroups.HierarchyPageMeta, error) {
	level, err := apiutil.ReadNumQuery[uint64](r, api.LevelKey, api.DefLevel)
	if err != nil {
		return mggroups.HierarchyPageMeta{}, errors.Wrap(apiutil.ErrValidation, err)
	}

	tree, err := apiutil.ReadBoolQuery(r, api.TreeKey, false)
	if err != nil {
		return mggroups.HierarchyPageMeta{}, errors.Wrap(apiutil.ErrValidation, err)
	}
	hierarchyDir, err := apiutil.ReadNumQuery[int64](r, api.DirKey, -1)
	if err != nil {
		return mggroups.HierarchyPageMeta{}, errors.Wrap(apiutil.ErrValidation, err)
	}

	return mggroups.HierarchyPageMeta{
		Level:     level,
		Direction: hierarchyDir,
		Tree:      tree,
	}, nil
}

func decodePageMeta(r *http.Request) (mggroups.PageMeta, error) {
	s, err := apiutil.ReadStringQuery(r, api.StatusKey, api.DefGroupStatus)
	if err != nil {
		return mggroups.PageMeta{}, errors.Wrap(apiutil.ErrValidation, err)
	}
	st, err := mgclients.ToStatus(s)
	if err != nil {
		return mggroups.PageMeta{}, errors.Wrap(apiutil.ErrValidation, err)
	}
	offset, err := apiutil.ReadNumQuery[uint64](r, api.OffsetKey, api.DefOffset)
	if err != nil {
		return mggroups.PageMeta{}, errors.Wrap(apiutil.ErrValidation, err)
	}
	limit, err := apiutil.ReadNumQuery[uint64](r, api.LimitKey, api.DefLimit)
	if err != nil {
		return mggroups.PageMeta{}, errors.Wrap(apiutil.ErrValidation, err)
	}
	name, err := apiutil.ReadStringQuery(r, api.NameKey, "")
	if err != nil {
		return mggroups.PageMeta{}, errors.Wrap(apiutil.ErrValidation, err)
	}
	id, err := apiutil.ReadStringQuery(r, api.IDOrder, "")
	if err != nil {
		return mggroups.PageMeta{}, errors.Wrap(apiutil.ErrValidation, err)
	}
	meta, err := apiutil.ReadMetadataQuery(r, api.MetadataKey, nil)
	if err != nil {
		return mggroups.PageMeta{}, errors.Wrap(apiutil.ErrValidation, err)
	}
	permission, err := apiutil.ReadStringQuery(r, api.PermissionKey, api.DefPermission)
	if err != nil {
		return mggroups.PageMeta{}, errors.Wrap(apiutil.ErrValidation, err)
	}
	listPerms, err := apiutil.ReadBoolQuery(r, api.ListPerms, api.DefListPerms)
	if err != nil {
		return mggroups.PageMeta{}, errors.Wrap(apiutil.ErrValidation, err)
	}
	ret := mggroups.PageMeta{
		Offset:     offset,
		Limit:      limit,
		Name:       name,
		ID:         id,
		Metadata:   meta,
		Status:     st,
		Permission: permission,
		ListPerms:  listPerms,
	}
	return ret, nil
}
