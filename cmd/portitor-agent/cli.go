// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
		Short:         "Show the firewall's state (read-only; changes go through portitor-web)",
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
			return nil, fmt.Errorf("%w (is portitor-agent running, and are you root?)", err)
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
		Short: "VRRP virtual routers and their state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			v, err := client().VRRP(ctx)
			if err != nil {
				return fmt.Errorf("%w (is portitor-agent running, and are you root?)", err)
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
				return fmt.Errorf("%w (is portitor-agent running, and are you root?)", err)
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
	return root
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
