// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/web"
)

// portalCommand is portitor-web's: the portal to the firewalls' own
// portitor-configs, and the witness of HA pairs (web.yaml).
func portalCommand() *cobra.Command {
	var configFile, bind string
	var debug bool
	root := &cobra.Command{
		Use:              "portitor-web",
		Short:            "Portitor: the portal to the firewalls' GUIs, and the HA pairs' witness",
		SilenceUsage:     true,
		SilenceErrors:    true,
		Version:          buildinfo.Version,
		PersistentPreRun: setLogging(&debug),
	}
	root.PersistentFlags().StringVarP(&configFile, "config", "f", web.DefaultConfigFile, "config file")
	root.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "debug logging")

	load := func() (*web.PortalConfig, error) {
		cfg, err := web.LoadPortalConfig(configFile)
		if err != nil {
			return nil, err
		}
		if bind != "" {
			cfg.Bind = bind
		}
		return cfg, nil
	}
	start := &cobra.Command{
		Use:   "start",
		Short: "Serve the firewalls' GUIs at /fw/<name>/, and be the witness of the pairs under witness:",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			p, err := web.NewPortal(cfg)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			return p.Serve(ctx)
		},
	}
	start.Flags().StringVarP(&bind, "bind", "b", "", "listen address (overrides config)")
	root.AddCommand(start)

	root.AddCommand(&cobra.Command{
		Use:   "witness",
		Short: "Only be the witness of the HA pairs under witness:, without the GUI",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			if len(cfg.Witness) == 0 {
				return fmt.Errorf("%s has no witness: entries (portitor-config witness-string on an HA primary)", configFile)
			}
			w, err := web.NewWitness(cfg.Witness)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			w.Run(ctx)
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "check",
		Short: "Check web.yaml and ask each firewall's portitor-config for its version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			p, err := web.NewPortal(cfg)
			if err != nil {
				return err
			}
			bad := 0
			for _, st := range p.Check(cmd.Context()) {
				if st.Error != "" {
					bad++
					fmt.Printf("%-16s %s\n", st.Name, st.Error)
					continue
				}
				fmt.Printf("%-16s portitor-config %s\n", st.Name, st.Version)
			}
			if bad > 0 {
				return fmt.Errorf("%d of %d firewalls do not answer", bad, len(cfg.Firewalls))
			}
			return nil
		},
	})
	return root
}
