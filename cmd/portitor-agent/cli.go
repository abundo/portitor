// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/abundo/portitor/internal/agent"
	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/render"
)

// cliCommand is the portitor command: portitor-agent run as "portitor"
// (a symlink). It reads the running agent's state over its local socket.
func cliCommand() *cobra.Command {
	var configFile, instance string
	var asJSON bool
	root := &cobra.Command{
		Use:           "portitor",
		Short:         "Show the firewall's state and act on it (configuration changes go through portitor-config)",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       buildinfo.Version,
	}
	root.PersistentFlags().StringVarP(&configFile, "config", "f", agent.DefaultConfigFile, "agent config file")
	root.PersistentFlags().StringVarP(&instance, "instance", "i", "", "only this instance")
	root.PersistentFlags().BoolVar(&asJSON, "json", false, "print JSON")

	client := func() *agentclient.Client {
		runDir := render.DefaultPaths().RunDir
		if cfg, err := agent.LoadConfig(configFile); err == nil {
			runDir = cfg.Paths.RunDir
		}
		return agentclient.NewLocal(filepath.Join(runDir, agent.SocketName))
	}
	neighbours := func(cmd *cobra.Command) (*agentapi.NeighboursResponse, error) {
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		n, err := client().Neighbours(ctx)
		if err != nil {
			return nil, hint(err)
		}
		return n, nil
	}

	show := &cobra.Command{Use: "show", Short: "Show state"}
	root.AddCommand(show)

	lldp := &cobra.Command{Use: "lldp", Short: "LLDP"}
	show.AddCommand(lldp)
	var detail bool
	lldpNeighbours := &cobra.Command{
		Use:     "neighbours",
		Aliases: []string{"neighbors", "neighbour", "neighbor", "nei"},
		Short:   "LLDP neighbours heard",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := neighbours(cmd)
			if err != nil {
				return err
			}
			var rows []agentapi.LLDPNeighbour
			for _, l := range n.LLDP {
				if instance == "" || l.Instance == instance {
					rows = append(rows, l)
				}
			}
			if asJSON {
				return printJSON(cmd.OutOrStdout(), rows)
			}
			if detail {
				printLLDPDetail(cmd.OutOrStdout(), rows)
			} else {
				printLLDP(cmd.OutOrStdout(), rows)
			}
			return nil
		},
	}
	lldpNeighbours.Flags().BoolVarP(&detail, "detail", "d", false, "everything the neighbour sent")
	lldp.AddCommand(lldpNeighbours)
	lldp.AddCommand(&cobra.Command{
		Use:     "interfaces",
		Aliases: []string{"ports"},
		Short:   "Interfaces LLDP runs on",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := neighbours(cmd)
			if err != nil {
				return err
			}
			var rows []agentapi.LLDPPort
			for _, p := range n.LLDPPorts {
				if instance == "" || p.Instance == instance {
					rows = append(rows, p)
				}
			}
			if asJSON {
				return printJSON(cmd.OutOrStdout(), rows)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "INSTANCE\tINTERFACE\tERROR")
			for _, p := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", p.Instance, p.Interface, p.Error)
			}
			return tw.Flush()
		},
	})

	ip := &cobra.Command{Use: "ip", Short: "IP"}
	show.AddCommand(ip)
	ip.AddCommand(&cobra.Command{
		Use:     "neighbours",
		Aliases: []string{"neighbors", "neighbour", "neighbor", "nei", "arp"},
		Short:   "ARP and ND tables",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := neighbours(cmd)
			if err != nil {
				return err
			}
			var rows []agentapi.IPNeighbour
			for _, e := range n.IP {
				if instance == "" || e.Instance == instance {
					rows = append(rows, e)
				}
			}
			if asJSON {
				return printJSON(cmd.OutOrStdout(), rows)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "INSTANCE\tINTERFACE\tADDRESS\tMAC\tSTATE")
			for _, e := range rows {
				state := e.State
				if e.Router {
					state += ",router"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Instance, e.Interface, e.Address, e.MAC, state)
			}
			return tw.Flush()
		},
	})
	show.AddCommand(&cobra.Command{
		Use:   "vrrp",
		Short: "VRRP and its state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			v, err := client().VRRP(ctx)
			if err != nil {
				return hint(err)
			}
			var rows []agentapi.VRRPInstance
			for _, in := range v.Instances {
				if instance == "" || in.Instance == instance {
					rows = append(rows, in)
				}
			}
			if asJSON {
				return printJSON(cmd.OutOrStdout(), rows)
			}
			printVRRP(cmd.OutOrStdout(), rows)
			return nil
		},
	})
	show.AddCommand(&cobra.Command{
		Use:   "bfd",
		Short: "BFD sessions and their state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			v, err := client().BFD(ctx)
			if err != nil {
				return hint(err)
			}
			var rows []agentapi.BFDInstance
			for _, in := range v.Instances {
				if instance == "" || in.Instance == instance {
					rows = append(rows, in)
				}
			}
			if asJSON {
				return printJSON(cmd.OutOrStdout(), rows)
			}
			printBFD(cmd.OutOrStdout(), rows)
			return nil
		},
	})
	show.AddCommand(&cobra.Command{
		Use:   "ha",
		Short: "This host's place in its HA pair and its quorum",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			st, err := client().HA(ctx)
			if err != nil {
				return hint(err)
			}
			if asJSON {
				return printJSON(cmd.OutOrStdout(), st)
			}
			printHA(cmd.OutOrStdout(), st)
			return nil
		},
	})
	addActions(root, client, &instance)
	return root
}

// addActions adds the commands that act without changing the
// configuration, for the console when portitor-web can't reach the
// firewall.
func addActions(root *cobra.Command, client func() *agentclient.Client, instance *string) {
	call := func(cmd *cobra.Command, f func(ctx context.Context, c *agentclient.Client) error) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
		defer cancel()
		if err := f(ctx, client()); err != nil {
			return hint(err)
		}
		return nil
	}
	// instanceName is --instance, or the default instance (the one in the
	// root namespace).
	instanceName := func(ctx context.Context, c *agentclient.Client) (string, error) {
		if *instance != "" {
			return *instance, nil
		}
		st, err := c.Status(ctx)
		if err != nil {
			return "", err
		}
		for _, in := range st.Instances {
			if in.Netns == "" {
				return in.Name, nil
			}
		}
		return "", errors.New("no default instance applied; name one with --instance")
	}

	root.AddCommand(&cobra.Command{
		Use:   "confirm",
		Short: "Confirm the pending commit",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return call(cmd, func(ctx context.Context, c *agentclient.Client) error {
				st, err := c.Status(ctx)
				if err != nil {
					return err
				}
				if st.Pending == nil {
					return errors.New("no commit is pending")
				}
				if err := c.Confirm(ctx, st.Pending.Generation); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Confirmed generation %d.\n", st.Pending.Generation)
				return nil
			})
		},
	})
	root.AddCommand(&cobra.Command{
		Use:   "rollback",
		Short: "Roll back to the last confirmed configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return call(cmd, func(ctx context.Context, c *agentclient.Client) error {
				res, err := c.Rollback(ctx)
				if err != nil {
					return err
				}
				for _, l := range res.Log {
					fmt.Fprintln(cmd.OutOrStdout(), clean(l))
				}
				if res.RollbackErrors != "" {
					return fmt.Errorf("rollback failed: %s", res.RollbackErrors)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Rolled back to generation %d.\n", res.Generation)
				return nil
			})
		},
	})

	request := &cobra.Command{Use: "request", Short: "Start an action"}
	root.AddCommand(request)
	dhcp := &cobra.Command{Use: "dhcp", Short: "DHCP client"}
	request.AddCommand(dhcp)
	var ipv6 bool
	renew := &cobra.Command{
		Use:   "renew <interface>",
		Short: "Renew the DHCP lease on an interface",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return call(cmd, func(ctx context.Context, c *agentclient.Client) error {
				name, err := instanceName(ctx, c)
				if err != nil {
					return err
				}
				req := agentapi.DHCPRenewRequest{Instance: name, Interface: args[0]}
				if ipv6 {
					req.Family = "ipv6"
				}
				if err := c.RenewDHCP(ctx, req); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Renewing %s in %s.\n", args[0], name)
				return nil
			})
		},
	}
	renew.Flags().BoolVarP(&ipv6, "ipv6", "6", false, "the DHCPv6 client")
	dhcp.AddCommand(renew)
	iplist := &cobra.Command{Use: "iplist", Short: "IP lists"}
	request.AddCommand(iplist)
	iplist.AddCommand(&cobra.Command{
		Use:   "update <name>",
		Short: "Download an IP list now",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return call(cmd, func(ctx context.Context, c *agentclient.Client) error {
				if err := c.RefreshIPList(ctx, args[0]); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Downloading %s.\n", args[0])
				return nil
			})
		},
	})
	blocklist := &cobra.Command{Use: "blocklist", Short: "DNS blocklists"}
	request.AddCommand(blocklist)
	blocklist.AddCommand(&cobra.Command{
		Use:   "update <name>",
		Short: "Download a DNS blocklist now",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return call(cmd, func(ctx context.Context, c *agentclient.Client) error {
				name, err := instanceName(ctx, c)
				if err != nil {
					return err
				}
				if err := c.RefreshDNSBlocklist(ctx, name, args[0]); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Downloading %s in %s.\n", args[0], name)
				return nil
			})
		},
	})

	// Break-glass for an HA host that hears neither its peer nor the
	// witness: it is fenced until it does, or until this vote ends.
	var minutes int
	haActive := &cobra.Command{
		Use:   "active",
		Short: "Let this HA host be active without its peer or the witness (logged)",
		Long: "Gives this HA host the witness's vote, so it stops fencing itself. " +
			"Only when the other host is known to be down: two active hosts answer for the same addresses.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return call(cmd, func(ctx context.Context, c *agentclient.Client) error {
				st, err := c.HAVote(ctx, minutes*60)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Active for %d minutes (fenced: %v).\n", minutes, st.Fenced)
				return nil
			})
		},
	}
	haActive.Flags().IntVar(&minutes, "minutes", 60, "how long")
	haReq := &cobra.Command{Use: "ha", Short: "HA pair"}
	haReq.AddCommand(haActive)
	request.AddCommand(haReq)

	clear := &cobra.Command{Use: "clear", Short: "Clear state"}
	root.AddCommand(clear)
	clear.AddCommand(&cobra.Command{
		Use:   "connections",
		Short: "Flush the connection tracking table",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return call(cmd, func(ctx context.Context, c *agentclient.Client) error {
				name, err := instanceName(ctx, c)
				if err != nil {
					return err
				}
				if err := c.FlushConnections(ctx, name); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Flushed the connection table of %s.\n", name)
				return nil
			})
		},
	})
}

// hint adds a reason to an error from not reaching the agent's socket;
// any other error stands as it is.
func hint(err error) error {
	var op *net.OpError
	if !errors.As(err, &op) {
		return err
	}
	return fmt.Errorf("%w (is portitor-agent running, and are you root?)", err)
}

func printHA(w io.Writer, st *agentapi.HAStatus) {
	if st.Node == "" {
		fmt.Fprintln(w, "Not in an HA pair.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Node:\t%s\n", st.Node)
	fmt.Fprintf(tw, "Epoch:\t%d\n", st.Epoch)
	if st.Stale {
		fmt.Fprintf(tw, "Stale:\tyes: the peer was promoted while this host was away; fenced until the new primary catches it up\n")
	}
	peer := "not heard"
	if st.PeerAlive {
		peer = "alive"
	}
	if st.PeerSeen != nil {
		peer += ", last heard " + st.PeerSeen.Local().Format(time.DateTime)
	}
	fmt.Fprintf(tw, "Peer:\t%s\n", peer)
	vote := "none"
	if st.VoteUntil != nil {
		vote = "until " + st.VoteUntil.Local().Format(time.DateTime)
	}
	fmt.Fprintf(tw, "Witness vote:\t%s\n", vote)
	fenced := "no"
	if st.Fenced {
		fenced = "yes: VRRP shut down, no DHCP or router advertisements"
	}
	fmt.Fprintf(tw, "Fenced:\t%s\n", fenced)
	tw.Flush()
}

func printBFD(w io.Writer, rows []agentapi.BFDInstance) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "INSTANCE\tINTERFACE\tPEER\tSTATUS\tUPTIME/DOWNTIME\tRX/TX (ms)\tMULTIPLIER\tDIAGNOSTIC")
	for _, in := range rows {
		if in.Error != "" {
			fmt.Fprintf(tw, "%s\t\t\t%s\t\t\t\t\n", in.Instance, clean(in.Error))
		}
		for _, p := range in.Peers {
			t := p.Uptime
			if p.Status != "up" {
				t = p.Downtime
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d/%d\t%d\t%s\n", in.Instance, clean(p.Interface), clean(p.Peer), clean(p.Status),
				time.Duration(t)*time.Second, p.ReceiveInterval, p.TransmitInterval, p.DetectMultiplier, clean(p.Diagnostic))
		}
	}
	tw.Flush()
}

func printVRRP(w io.Writer, rows []agentapi.VRRPInstance) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "INSTANCE\tINTERFACE\tVRID\tFAMILY\tSTATE\tPRIORITY\tADDRESSES")
	for _, in := range rows {
		if in.Error != "" {
			fmt.Fprintf(tw, "%s\t\t\t\t%s\t\t\n", in.Instance, clean(in.Error))
		}
		for _, r := range in.Routers {
			for _, f := range []struct {
				name string
				info *agentapi.VRRPFamilyInfo
			}{{"ipv4", r.V4}, {"ipv6", r.V6}} {
				if f.info == nil {
					continue
				}
				state := f.info.State
				if r.Shutdown {
					state += " (shut down)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%d\t%s\n", in.Instance, r.Interface, r.VRID, f.name, clean(state),
					f.info.EffectivePriority, strings.Join(f.info.Addresses, ","))
			}
		}
	}
	tw.Flush()
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printLLDP(w io.Writer, rows []agentapi.LLDPNeighbour) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "INSTANCE\tINTERFACE\tSYSTEM\tPORT\tPORT DESCRIPTION\tCAPABILITIES\tMANAGEMENT")
	for _, l := range rows {
		system := l.SystemName
		if system == "" {
			system = l.ChassisID
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", l.Instance, l.Interface, clean(system), clean(l.PortID),
			clean(l.PortDescription), strings.Join(l.EnabledCapabilities, ","), strings.Join(l.ManagementAddresses, ","))
	}
	tw.Flush()
}

func printLLDPDetail(w io.Writer, rows []agentapi.LLDPNeighbour) {
	for i, l := range rows {
		if i > 0 {
			fmt.Fprintln(w)
		}
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		line := func(k, v string) {
			if v != "" && v != "0" {
				fmt.Fprintf(tw, "%s:\t%s\n", k, clean(v))
			}
		}
		line("Interface", l.Instance+" "+l.Interface)
		line("Source MAC", l.SourceMAC)
		line("Chassis ID", l.ChassisID+" ("+l.ChassisIDSubtype+")")
		line("Port ID", l.PortID+" ("+l.PortIDSubtype+")")
		line("Port description", l.PortDescription)
		line("System name", l.SystemName)
		line("System description", l.SystemDescription)
		line("Capabilities", strings.Join(l.Capabilities, ", "))
		line("Enabled", strings.Join(l.EnabledCapabilities, ", "))
		line("Management", strings.Join(l.ManagementAddresses, ", "))
		line("Port VLAN", fmt.Sprint(l.PortVLAN))
		line("VLANs", strings.Join(l.VLANNames, ", "))
		line("Max frame size", fmt.Sprint(l.MaxFrame))
		line("TTL", fmt.Sprintf("%ds", l.TTL))
		line("First seen", l.FirstSeen.Local().Format(time.DateTime))
		line("Last seen", l.LastSeen.Local().Format(time.DateTime))
		line("Expires", l.Expires.Local().Format(time.DateTime))
		tw.Flush()
	}
}

// clean keeps what a neighbour sent from moving the terminal's cursor
// or breaking the table.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return ' '
		}
		return r
	}, s)
}
