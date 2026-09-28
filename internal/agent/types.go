// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import "github.com/abundo/portitor/internal/agentapi"

type (
	Status         = agentapi.Status
	PendingStatus  = agentapi.PendingStatus
	InstanceStatus = agentapi.InstanceStatus
	IfaceStatus    = agentapi.IfaceStatus
	RouteStatus    = agentapi.RouteStatus
	WGStatus       = agentapi.WGStatus
	WGPeerStatus   = agentapi.WGPeerStatus
	ServerLease    = agentapi.ServerLease
	Lease          = agentapi.Lease
	RenderResult   = agentapi.RenderResult
	ApplyResult    = agentapi.ApplyResult
	ProgramStatus  = agentapi.ProgramStatus
)
