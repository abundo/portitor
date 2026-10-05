// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import "github.com/abundo/portitor/internal/agentapi"

type (
	Status              = agentapi.Status
	PendingStatus       = agentapi.PendingStatus
	InstanceStatus      = agentapi.InstanceStatus
	IfaceStatus         = agentapi.IfaceStatus
	RouteStatus         = agentapi.RouteStatus
	WGStatus            = agentapi.WGStatus
	WGPeerStatus        = agentapi.WGPeerStatus
	ServerLease         = agentapi.ServerLease
	Lease               = agentapi.Lease
	DHCPOption          = agentapi.DHCPOption
	RenderResult        = agentapi.RenderResult
	ParseNftablesResult = agentapi.ParseNftablesResult
	ApplyResult         = agentapi.ApplyResult
	ProgramStatus       = agentapi.ProgramStatus
	NICStatus           = agentapi.NICStatus
	DynDNSStatus        = agentapi.DynDNSStatus
	TunnelBrokerStatus  = agentapi.TunnelBrokerStatus
	CertificateStatus   = agentapi.CertificateStatus
	IPListStatus        = agentapi.IPListStatus
	TaskStatus          = agentapi.TaskStatus
)
