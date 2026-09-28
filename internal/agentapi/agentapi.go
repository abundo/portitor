// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package agentapi is the wire format of portitor-agent's management API,
// shared by the agent and its client in portitor-web.
package agentapi

import (
	"time"

	"github.com/abundo/portitor/internal/dyndns"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

type ApplyRequest struct {
	Document fwconfig.Document `json:"document"`
	// ConfirmTimeoutSeconds > 0 rolls the change back unless confirmed.
	ConfirmTimeoutSeconds int `json:"confirm_timeout_seconds"`
}

type RenderRequest struct {
	Document fwconfig.Document `json:"document"`
}

type ConfirmRequest struct {
	Generation int64 `json:"generation"`
}

type LeasesResponse struct {
	Client []Lease                  `json:"client"`
	Server map[string][]ServerLease `json:"server"`
}

// RuleCountersResponse is the traffic of each rule with an ID
// (fwconfig.Rule.ID) since it was last applied.
type RuleCountersResponse struct {
	Rules map[uint32]RuleCounters `json:"rules"`
	// Drops is what each instance's filter chains dropped by themselves,
	// by instance name and then chain (input, forward, output).
	Drops map[string]map[string]ChainDrops `json:"drops"`
}

// ChainDrops counts the packets a filter chain dropped outside the rules:
// Invalid those of no known connection (ct state invalid), Policy those no
// rule decided on (the chain's drop policy).
type ChainDrops struct {
	InvalidPackets uint64 `json:"invalid_packets"`
	InvalidBytes   uint64 `json:"invalid_bytes"`
	PolicyPackets  uint64 `json:"policy_packets"`
	PolicyBytes    uint64 `json:"policy_bytes"`
}

// RuleCounters counts a rule's traffic: Orig what the rule matched and the
// rest of the connections it accepted in the same direction, sent by the
// side that opened them; Reply the replies. Only accept rules have replies.
type RuleCounters struct {
	OrigPackets  uint64 `json:"orig_packets"`
	OrigBytes    uint64 `json:"orig_bytes"`
	ReplyPackets uint64 `json:"reply_packets"`
	ReplyBytes   uint64 `json:"reply_bytes"`
}

type ErrorResponse struct {
	Error    string   `json:"error"`
	Problems []string `json:"problems,omitempty"`
}

type Status struct {
	Hostname   string           `json:"hostname"`
	Version    string           `json:"version"`
	DryRun     bool             `json:"dry_run"`
	Generation int64            `json:"generation"`
	LastApply  *time.Time       `json:"last_apply,omitempty"`
	LastError  string           `json:"last_error,omitempty"`
	Pending    *PendingStatus   `json:"pending,omitempty"`
	Instances  []InstanceStatus `json:"instances"`
	DHCPLeases []Lease          `json:"dhcp_client_leases"`
	DynDNS     []DynDNSStatus   `json:"dyndns"`
	IPLists    []IPListStatus   `json:"ip_lists"`
	Tasks      []TaskStatus     `json:"tasks"`
	Programs   []ProgramStatus  `json:"programs"`
	// NICs are the physical interfaces on the firewall, wherever they are.
	NICs []NICStatus `json:"nics"`
	// AntiLockout is the input rule the agent adds in the default
	// instance for its API port; nil when disabled.
	AntiLockout *render.AntiLockout `json:"anti_lockout,omitempty"`
}

// NICStatus is a physical interface: a real NIC (no link kind), or one the
// applied document declares physical (in a container it may be a veth).
type NICStatus struct {
	Name string `json:"name"`
	// Netns is empty for the root namespace.
	Netns string `json:"netns,omitempty"`
	MAC   string `json:"mac,omitempty"`
	State string `json:"state"`
	// Up is the administrative state (IFF_UP), which the agent sets from
	// Interface.Enabled; State is the operational one.
	Up  bool `json:"up"`
	MTU int  `json:"mtu"`
	// Addresses are the static addresses (CIDR), link-local excluded.
	Addresses []string `json:"addresses"`
	// DHCPv4 and SLAAC: the interface has a dynamic address of that family.
	DHCPv4 bool `json:"dhcpv4,omitempty"`
	SLAAC  bool `json:"slaac,omitempty"`
}

// ProgramStatus is an external program the agent depends on.
type ProgramStatus struct {
	Name    string `json:"name"`
	Purpose string `json:"purpose"`
	// Path is empty when the program is not installed.
	Path string `json:"path,omitempty"`
	// Needed: the applied configuration uses it.
	Needed bool `json:"needed"`
}

type PendingStatus struct {
	Generation int64     `json:"generation"`
	Deadline   time.Time `json:"deadline"`
}

type InstanceStatus struct {
	Name       string            `json:"name"`
	Netns      string            `json:"netns,omitempty"`
	Interfaces []IfaceStatus     `json:"interfaces"`
	Routes     []RouteStatus     `json:"routes"`
	WireGuard  []WGStatus        `json:"wireguard"`
	Services   map[string]string `json:"services"`
}

type IfaceStatus struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind,omitempty"`
	State     string   `json:"state"`
	MTU       int      `json:"mtu"`
	MAC       string   `json:"mac,omitempty"`
	Addresses []string `json:"addresses"`
	RxBytes   uint64   `json:"rx_bytes"`
	TxBytes   uint64   `json:"tx_bytes"`
}

type RouteStatus struct {
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway,omitempty"`
	Dev      string `json:"dev,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type WGStatus struct {
	Interface  string         `json:"interface"`
	PublicKey  string         `json:"public_key"`
	ListenPort int            `json:"listen_port"`
	Peers      []WGPeerStatus `json:"peers"`
}

type WGPeerStatus struct {
	PublicKey       string     `json:"public_key"`
	Endpoint        string     `json:"endpoint,omitempty"`
	AllowedIPs      []string   `json:"allowed_ips"`
	LatestHandshake *time.Time `json:"latest_handshake,omitempty"`
	RxBytes         uint64     `json:"rx_bytes"`
	TxBytes         uint64     `json:"tx_bytes"`
}

// ServerLease is an active lease handed out by Kea.
type ServerLease struct {
	Address  string    `json:"address"`
	MAC      string    `json:"mac"`
	Hostname string    `json:"hostname,omitempty"`
	Expires  time.Time `json:"expires"`
}

// Lease is what the DHCP client learned on one interface.
type Lease struct {
	Instance   string    `json:"instance"`
	Interface  string    `json:"interface"`
	Address    string    `json:"address"` // CIDR
	Router     string    `json:"router,omitempty"`
	DNS        []string  `json:"dns,omitempty"`
	Server     string    `json:"server,omitempty"`
	Obtained   time.Time `json:"obtained"`
	Expires    time.Time `json:"expires"`
	State      string    `json:"state"` // requesting, bound, error
	LastError  string    `json:"last_error,omitempty"`
	RenewAfter time.Time `json:"renew_after"`
}

// DynDNSStatus is the state of a dynamic DNS client.
type DynDNSStatus struct {
	Instance  string `json:"instance"`
	Name      string `json:"name"`
	Interface string `json:"interface"`
	dyndns.Status
}

// IPListStatus is the state of an IP list's download.
type IPListStatus struct {
	Name string `json:"name"`
	// State: pending (not downloaded yet), fetching, ok, error.
	State string `json:"state"`
	// Updated is the last successful download, whose counts follow.
	Updated *time.Time `json:"updated,omitempty"`
	IPv4    int        `json:"ipv4"`
	IPv6    int        `json:"ipv6"`
	// Skipped entries were not addresses, or not IP/range bans.
	Skipped     int        `json:"skipped"`
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

// TaskStatus is the state of a scheduled task.
type TaskStatus struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Schedule string `json:"schedule"`
	// Next is when it runs next, in the firewall's time zone; nil when
	// the schedule never fires.
	Next    *time.Time `json:"next,omitempty"`
	Running bool       `json:"running"`
	// LastStart and LastEnd are of the last run; LastResult is ok or
	// error (LastError says why).
	LastStart  *time.Time `json:"last_start,omitempty"`
	LastEnd    *time.Time `json:"last_end,omitempty"`
	LastResult string     `json:"last_result,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	// Output is the end of a command's output (stdout and stderr).
	Output string `json:"output,omitempty"`
}

// RunRequest names a task to run now (/v1/tasks/run) or an IP list to
// download now (/v1/iplists/refresh). Both answer 202 once started.
type RunRequest struct {
	Name string `json:"name"`
}

// RenderResult is a preview: the files a document would produce next to
// the files currently applied.
type RenderResult struct {
	Files   []render.File `json:"files"`
	Current []render.File `json:"current"`
}

type ApplyResult struct {
	Generation     int64      `json:"generation"`
	Log            []string   `json:"log"`
	ConfirmBy      *time.Time `json:"confirm_by,omitempty"`
	RolledBack     bool       `json:"rolled_back,omitempty"`
	RollbackErrors string     `json:"rollback_error,omitempty"`
}

// LogEntry is one record of the agent's log. Ids increase across agent
// restarts (they start at the start time in microseconds).
type LogEntry struct {
	ID      int64             `json:"id"`
	Time    time.Time         `json:"time"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Attrs   map[string]string `json:"attrs,omitempty"`
}

// LogsResponse holds the log entries after the id asked for.
type LogsResponse struct {
	Entries []LogEntry `json:"entries"`
}

// PacketLogEntry is a packet a ruleset logged: by a rule with Log set, or a
// built-in one the instance logs (a chain's invalid or policy drops, an
// auto input rule). Ids increase like LogEntry's.
type PacketLogEntry struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Instance string    `json:"instance"`
	Chain    string    `json:"chain"`
	// Rule is the rule's number, as in the ruleset's comments, or 0 for a
	// built-in rule: Builtin is then policy, invalid or auto, and Service
	// the auto input rule's service.
	Rule         int    `json:"rule,omitempty"`
	Builtin      string `json:"builtin,omitempty"`
	Service      string `json:"service,omitempty"`
	Action       string `json:"action"`
	InInterface  string `json:"in_interface,omitempty"`
	OutInterface string `json:"out_interface,omitempty"`
	Family       string `json:"family"`   // ipv4, ipv6
	Protocol     string `json:"protocol"` // tcp, udp, icmp, ipv6-icmp, ... or the number
	Src          string `json:"src"`
	Dst          string `json:"dst"`
	SrcPort      uint16 `json:"src_port,omitempty"`
	DstPort      uint16 `json:"dst_port,omitempty"`
	// DstService is the destination port's name in the agent's
	// /etc/services ("https"), if it has one.
	DstService string `json:"dst_service,omitempty"`
	// Info is the TCP flags ("SYN") or the ICMP type and code ("type 8
	// code 0").
	Info   string `json:"info,omitempty"`
	Length int    `json:"length"` // of the IP packet
}

// PacketLogResponse holds the packet log entries after the id asked for.
type PacketLogResponse struct {
	Entries []PacketLogEntry `json:"entries"`
}

// ConsoleResize is the one text message on the console WebSocket
// (/v1/console, and /api/agent/console in portitor-web, which passes
// messages through). Binary messages are terminal data both ways.
type ConsoleResize struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// SystemStatus is the firewall's operating system, the package upgrades apt
// offers, the Portitor releases from the last check, and the update jobs
// (GET /v1/system).
type SystemStatus struct {
	OS             string     `json:"os"`
	Kernel         string     `json:"kernel"`
	BootTime       *time.Time `json:"boot_time,omitempty"`
	RebootRequired bool       `json:"reboot_required"`
	// Packages are the upgrades in apt's package lists (as of the last
	// `apt-get update`, which a check runs).
	Packages []PackageUpgrade `json:"packages"`
	// Releases is `install.py --list --json` from the last check; nil
	// before one, or when it failed (ReleasesError).
	Releases      *Releases `json:"releases,omitempty"`
	ReleasesError string    `json:"releases_error,omitempty"`
	// Installer tells whether /usr/lib/portitor/install.py is there.
	Installer bool        `json:"installer"`
	Jobs      []SystemJob `json:"jobs"`
}

type PackageUpgrade struct {
	Name     string `json:"name"`
	From     string `json:"from"`
	To       string `json:"to"`
	Security bool   `json:"security"`
}

// Releases is install.py's `--list --json` output.
type Releases struct {
	// Installed maps "web" and "agent" to the version installed on the
	// firewall host (only the parts that are installed there).
	Installed map[string]string `json:"installed"`
	Latest    string            `json:"latest"`
	Releases  []Release         `json:"releases"`
}

type Release struct {
	Tag         string `json:"tag"`
	Date        string `json:"date"`
	Prerelease  bool   `json:"prerelease"`
	Notes       string `json:"notes"`
	Newer       bool   `json:"newer"`
	Installable bool   `json:"installable"`
}

// Update jobs.
const (
	// JobCheck runs apt-get update and lists the Portitor releases.
	JobCheck = "check"
	// JobUpgrade upgrades the Debian packages.
	JobUpgrade = "upgrade"
	// JobUpdate installs a Portitor release (SystemJobRequest.Release).
	JobUpdate = "update"
)

// Job states.
const (
	JobRunning   = "running"
	JobSucceeded = "succeeded"
	JobFailed    = "failed"
)

// SystemJob is the latest run of an update job.
type SystemJob struct {
	Name     string     `json:"name"`
	State    string     `json:"state"`
	Started  *time.Time `json:"started,omitempty"`
	Finished *time.Time `json:"finished,omitempty"`
	// Output is the end of what the job printed.
	Output string `json:"output"`
}

// SystemJobRequest starts an update job (POST /v1/system/jobs).
type SystemJobRequest struct {
	Job     string `json:"job"`
	Release string `json:"release,omitempty"`
}
