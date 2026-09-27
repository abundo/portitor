// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// portitor-agent runs on the firewall. It applies configuration pushed by
// portitor-web and reports status. See AGENTS.md for the architecture.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/abundo/portitor/internal/agent"
	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

func main() {
	var configFile string
	root := &cobra.Command{
		Use:           "portitor-agent",
		Short:         "Portitor agent: applies configuration from portitor-web",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       buildinfo.Version,
	}
	root.PersistentFlags().StringVarP(&configFile, "config", "f", agent.DefaultConfigFile, "config file")

	root.AddCommand(&cobra.Command{
		Use:   "start",
		Short: "Run the agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := agent.LoadConfig(configFile)
			if err != nil {
				return err
			}
			setupLog(cfg.LogLevel)
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			a := agent.New(cfg)
			defer a.Stop()
			if err := a.Start(ctx); err != nil {
				// Keep serving: the GUI is how the operator fixes it.
				slog.Error("restoring configuration failed", "err", err)
			}
			return a.Serve(ctx)
		},
	})

	var hosts []string
	var tokenFile, certFile, keyFile string
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create the API token and TLS certificate, and print what portitor-web needs",
		RunE: func(cmd *cobra.Command, args []string) error {
			token, fp, err := agent.InitFiles(tokenFile, certFile, keyFile, hosts)
			if err != nil {
				return err
			}
			fmt.Printf("token:       %s\nfingerprint: %s\n", token, fp)
			fmt.Println("\nEnter both under Settings > Agent in portitor-web.")
			return nil
		},
	}
	initCmd.Flags().StringSliceVar(&hosts, "host", nil, "names/addresses for the certificate (repeatable)")
	initCmd.Flags().StringVar(&tokenFile, "token-file", "/etc/portitor/agent.token", "")
	initCmd.Flags().StringVar(&certFile, "tls-cert", "/etc/portitor/agent.crt", "")
	initCmd.Flags().StringVar(&keyFile, "tls-key", "/etc/portitor/agent.key", "")
	root.AddCommand(initCmd)

	var sample bool
	renderCmd := &cobra.Command{
		Use:   "render [document.json]",
		Short: "Render a document to stdout without applying it",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var doc fwconfig.Document
			switch {
			case sample:
				doc = fwconfig.SampleDocument()
			case len(args) == 1:
				data, err := os.ReadFile(args[0])
				if err != nil {
					return err
				}
				if err := json.Unmarshal(data, &doc); err != nil {
					return err
				}
			default:
				return fmt.Errorf("give a document file or --sample")
			}
			b, err := render.Render(doc, render.Options{Paths: render.DefaultPaths(), Units: render.DefaultUnits()})
			if err != nil {
				return err
			}
			for _, f := range b.Redacted() {
				fmt.Printf("===== %s =====\n%s\n", f.Path, f.Content)
			}
			return nil
		},
	}
	renderCmd.Flags().BoolVar(&sample, "sample", false, "render the built-in sample document")
	root.AddCommand(renderCmd)

	var stateDir string
	nsExec := &cobra.Command{
		Use:                "netns-exec <instance> -- <command> [args...]",
		Short:              "Exec a command in an instance's network namespace (used by systemd units)",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && strings.HasPrefix(args[0], "--state-dir=") {
				stateDir = strings.TrimPrefix(args[0], "--state-dir=")
				args = args[1:]
			}
			if len(args) < 3 || args[1] != "--" {
				return fmt.Errorf("usage: portitor-agent netns-exec [--state-dir=DIR] <instance> -- <command> [args...]")
			}
			return agent.NetnsExec(stateDir, args[0], args[2:])
		},
	}
	stateDir = render.DefaultPaths().StateDir
	root.AddCommand(nsExec)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func setupLog(level string) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}
