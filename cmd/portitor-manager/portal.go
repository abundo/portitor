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

// portalCommand is portitor-manager's: the manager of the firewalls' own
// portitor-configs, and the witness of firewall clusters (manager.yaml).
func portalCommand() *cobra.Command {
	var configFile, bind string
	var debug bool
	root := &cobra.Command{
		Use:              "portitor-manager",
		Short:            "Portitor: the manager of the firewalls, and the firewall clusters' witness",
		SilenceUsage:     true,
		SilenceErrors:    true,
		Version:          buildinfo.Version,
		PersistentPreRun: setLogging(&debug),
	}
	root.PersistentFlags().StringVarP(&configFile, "config", "f", web.DefaultConfigFile, "config file (before 1.1.0 "+web.OldConfigFile+", still read when it is missing)")
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
		Short: "Serve portitor-manager: the firewalls' GUIs as tabs, at /fw/<name>/, and be the firewall clusters' witness",
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
		Short: "Only be the witness of the firewall clusters given by add-witness, without the GUI",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			store, err := openStore(cfg)
			if err != nil {
				return err
			}
			if len(store.Witnesses()) == 0 {
				return fmt.Errorf("no witness strings in %s (portitor-manager add-witness, from portitor-config witness-string on a cluster primary)", cfg.DataDir)
			}
			w, err := web.NewWitness(store.Witnesses())
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
		Use:   "createadmin <user>",
		Short: "Make a portitor-manager user, or change their password (read from the terminal or standard input)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			store, err := openStore(cfg)
			if err != nil {
				return err
			}
			pw, err := readPassword()
			if err != nil {
				return err
			}
			if err := web.CreatePortalUser(store, args[0], pw); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	})

	var addDesc, addFP string
	addFW := &cobra.Command{
		Use:   "add-firewall <name> <url>",
		Short: "Add or change a firewall by its portitor-config URL and certificate fingerprint (the GUI reads them over SSH)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			store, err := openStore(cfg)
			if err != nil {
				return err
			}
			f := web.PortalFirewall{Name: args[0], URL: args[1], Fingerprint: addFP, Description: addDesc}
			if err := web.CheckPortalFirewall(&f); err != nil {
				return err
			}
			return store.PutFirewall(f)
		},
	}
	addFW.Flags().StringVar(&addFP, "fingerprint", "", "SHA-256 of its tls_cert (portitor-config fingerprint there)")
	addFW.Flags().StringVar(&addDesc, "description", "", "description")
	root.AddCommand(addFW)

	root.AddCommand(&cobra.Command{
		Use:   "cli",
		Short: "portitor-manager's configuration CLI (the same as portitor-config cli); it reads commands from stdin when that is not a terminal",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			store, err := openStore(cfg)
			if err != nil {
				return err
			}
			return runCLI(cmd.Context(), store.CLIEnv("console"))
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "list-firewalls",
		Short: "Print the firewalls, one per line: name and URL (install.py reads them)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			store, err := openStore(cfg)
			if err != nil {
				return err
			}
			for _, f := range store.Firewalls() {
				fmt.Fprintln(cmd.OutOrStdout(), f.Name, f.URL)
			}
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "add-witness <witness string>",
		Short: "Be the witness of a firewall cluster (portitor-config witness-string on its primary)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			store, err := openStore(cfg)
			if err != nil {
				return err
			}
			return store.PutWitness(args[0])
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "check",
		Short: "Check the configuration and ask each firewall's portitor-config for its version",
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
			if len(p.Check(cmd.Context())) == 0 {
				fmt.Println("no firewalls")
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
				return fmt.Errorf("%d firewalls do not answer", bad)
			}
			return nil
		},
	})
	return root
}

// openStore opens the portal's configuration, taking in an older web.yaml's
// lists the first time.
func openStore(cfg *web.PortalConfig) (*web.PortalStore, error) {
	return web.OpenPortalConfigStore(cfg)
}
