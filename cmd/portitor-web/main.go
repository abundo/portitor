// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// portitor-web is the management GUI and API. It runs off the firewall and
// pushes configuration to portitor-agent. See AGENTS.md.
package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/dbmigrate"
	"github.com/abundo/portitor/models"
	"github.com/abundo/portitor/web"
)

func main() {
	var configFile, bind string
	var debug bool
	root := &cobra.Command{
		Use:           "portitor-web",
		Short:         "Portitor management GUI",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       buildinfo.Version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			level := slog.LevelInfo
			if debug {
				level = slog.LevelDebug
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
		},
	}
	root.PersistentFlags().StringVarP(&configFile, "config", "f", web.DefaultConfigFile, "config file")
	root.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "debug logging")

	load := func() (*web.Config, *web.Server, error) {
		cfg, err := web.LoadConfig(configFile)
		if err != nil {
			return nil, nil, err
		}
		if bind != "" {
			cfg.Bind = bind
		}
		db, err := web.ConnectDB(cfg.DB)
		if err != nil {
			return nil, nil, err
		}
		return cfg, web.NewServer(cfg, db), nil
	}

	start := &cobra.Command{
		Use:   "start",
		Short: "Serve the GUI and API (run `migrate` first after upgrades)",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, srv, err := load()
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			return srv.Serve(ctx)
		},
	}
	start.Flags().StringVarP(&bind, "bind", "b", "", "listen address (overrides config)")
	root.AddCommand(start)

	root.AddCommand(&cobra.Command{
		Use:   "migrate",
		Short: "Apply database schema migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := web.LoadConfig(configFile)
			if err != nil {
				return err
			}
			db, err := web.ConnectDB(cfg.DB)
			if err != nil {
				return err
			}
			return dbmigrate.Up(db)
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "createadmin <username>",
		Short: "Create a user, or reset an existing user's password",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, srv, err := load()
			if err != nil {
				return err
			}
			pw, err := readPassword()
			if err != nil {
				return err
			}
			if err := web.CreateUser(srv, args[0], pw); err != nil {
				return err
			}
			fmt.Println("user", args[0], "saved")
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "agent-url",
		Short: "Print the agent URL from the settings (install.py updates that host)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := web.LoadConfig(configFile)
			if err != nil {
				return err
			}
			db, err := web.ConnectDB(cfg.DB)
			if err != nil {
				return err
			}
			var urls []string
			if err := db.Model(&models.Settings{}).Where("id = ?", 1).Pluck("agent_url", &urls).Error; err != nil {
				return err
			}
			if len(urls) > 0 {
				fmt.Println(urls[0])
			}
			return nil
		},
	})

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

// readPassword prompts on a terminal, or reads one line from stdin.
func readPassword() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		a, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		fmt.Fprint(os.Stderr, "Again: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(a) != string(b) {
			return "", fmt.Errorf("passwords differ")
		}
		return string(a), nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
