// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	authn "github.com/absmach/supermq/pkg/authn"

	invitations "github.com/absmach/supermq/invitations"

	mock "github.com/stretchr/testify/mock"
)

// Service is an autogenerated mock type for the Service type
type Service struct {
	mock.Mock
}

// AcceptInvitation provides a mock function with given fields: ctx, session, domainID
func (_m *Service) AcceptInvitation(ctx context.Context, session authn.Session, domainID string) error {
	ret := _m.Called(ctx, session, domainID)

	if len(ret) == 0 {
		panic("no return value specified for AcceptInvitation")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string) error); ok {
		r0 = rf(ctx, session, domainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteInvitation provides a mock function with given fields: ctx, session, userID, domainID
func (_m *Service) DeleteInvitation(ctx context.Context, session authn.Session, userID string, domainID string) error {
	ret := _m.Called(ctx, session, userID, domainID)

	if len(ret) == 0 {
		panic("no return value specified for DeleteInvitation")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string) error); ok {
		r0 = rf(ctx, session, userID, domainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ListInvitations provides a mock function with given fields: ctx, session, page
func (_m *Service) ListInvitations(ctx context.Context, session authn.Session, page invitations.Page) (invitations.InvitationPage, error) {
	ret := _m.Called(ctx, session, page)

	if len(ret) == 0 {
		panic("no return value specified for ListInvitations")
	}

	var r0 invitations.InvitationPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, invitations.Page) (invitations.InvitationPage, error)); ok {
		return rf(ctx, session, page)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, invitations.Page) invitations.InvitationPage); ok {
		r0 = rf(ctx, session, page)
	} else {
		r0 = ret.Get(0).(invitations.InvitationPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, invitations.Page) error); ok {
		r1 = rf(ctx, session, page)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RejectInvitation provides a mock function with given fields: ctx, session, domainID
func (_m *Service) RejectInvitation(ctx context.Context, session authn.Session, domainID string) error {
	ret := _m.Called(ctx, session, domainID)

	if len(ret) == 0 {
		panic("no return value specified for RejectInvitation")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string) error); ok {
		r0 = rf(ctx, session, domainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SendInvitation provides a mock function with given fields: ctx, session, invitation
func (_m *Service) SendInvitation(ctx context.Context, session authn.Session, invitation invitations.Invitation) error {
	ret := _m.Called(ctx, session, invitation)

	if len(ret) == 0 {
		panic("no return value specified for SendInvitation")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, invitations.Invitation) error); ok {
		r0 = rf(ctx, session, invitation)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ViewInvitation provides a mock function with given fields: ctx, session, userID, domainID
func (_m *Service) ViewInvitation(ctx context.Context, session authn.Session, userID string, domainID string) (invitations.Invitation, error) {
	ret := _m.Called(ctx, session, userID, domainID)

	if len(ret) == 0 {
		panic("no return value specified for ViewInvitation")
	}

	var r0 invitations.Invitation
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string) (invitations.Invitation, error)); ok {
		return rf(ctx, session, userID, domainID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string) invitations.Invitation); ok {
		r0 = rf(ctx, session, userID, domainID)
	} else {
		r0 = ret.Get(0).(invitations.Invitation)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string, string) error); ok {
		r1 = rf(ctx, session, userID, domainID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewService creates a new instance of Service. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewService(t interface {
	mock.TestingT
	Cleanup(func())
}) *Service {
	mock := &Service{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
