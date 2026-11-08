// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/abundo/portitor/internal/cli"
	"github.com/abundo/portitor/web"
)

// addConsoleCommands adds configuration from the console: one API request
// in-process as the console admin (web.ConsoleRequest). On a firewall,
// portitor-config's: its own configuration even when its manager can't
// be reached.
func addConsoleCommands(root *cobra.Command, load func() (*web.Config, *web.Server, error)) {
	request := func(cmd *cobra.Command, method, path string, body any) (map[string]any, []map[string]any, error) {
		_, srv, err := load()
		if err != nil {
			return nil, nil, err
		}
		var data []byte
		if body != nil {
			if data, err = json.Marshal(body); err != nil {
				return nil, nil, err
			}
		}
		code, out := srv.ConsoleRequest(cmd.Context(), method, path, data)
		if code/100 != 2 {
			var e struct {
				Error    string   `json:"error"`
				Problems []string `json:"problems"`
			}
			_ = json.Unmarshal(out, &e)
			msg := e.Error
			if msg == "" {
				msg = strings.TrimSpace(string(out))
			}
			if len(e.Problems) > 0 {
				msg += ":\n  " + strings.Join(e.Problems, "\n  ")
			}
			return nil, nil, fmt.Errorf("%s %s: %d %s", method, path, code, msg)
		}
		var obj map[string]any
		if json.Unmarshal(out, &obj) == nil {
			return obj, nil, nil
		}
		var list []map[string]any
		_ = json.Unmarshal(out, &list)
		return nil, list, nil
	}
	print := func(cmd *cobra.Command, obj map[string]any, list []map[string]any) error {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		if obj != nil {
			return enc.Encode(obj)
		}
		return enc.Encode(list)
	}

	root.AddCommand(&cobra.Command{
		Use:   "api METHOD PATH [JSON|-]",
		Short: "Send one API request as the console admin (e.g. api GET /api/interfaces)",
		Args:  cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			var body any
			if len(args) == 3 {
				raw := []byte(args[2])
				if args[2] == "-" {
					var err error
					if raw, err = io.ReadAll(os.Stdin); err != nil {
						return err
					}
				}
				if err := json.Unmarshal(raw, &body); err != nil {
					return fmt.Errorf("body: %w", err)
				}
			}
			obj, list, err := request(cmd, strings.ToUpper(args[0]), args[1], body)
			if err != nil {
				return err
			}
			return print(cmd, obj, list)
		},
	})

	var vf string
	set := &cobra.Command{
		Use:   "set RESOURCE NAME KEY=VALUE...",
		Short: "Change leaves of a configuration entry found by its key (e.g. set interfaces ens19 addresses=192.168.1.1/24)",
		Long: "RESOURCE is a list of the configuration (interface, rule, route, host, ...; plurals and the " +
			"API's collection names work too); NAME its entry's key (keys joined by \",\"), in the virtual " +
			"firewall --vf (default: the host) for a virtual firewall's list. KEY is a leaf (kebab or snake " +
			"case); a leaf-list takes comma-separated values (empty: none); an empty value unsets a leaf. " +
			"The entry is made when it isn't there. Commit after.",
		Args: cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, srv, err := load()
			if err != nil {
				return err
			}
			path, leafLists, err := srv.ConsoleSetPath(cmd.Context(), vf, strings.Trim(args[0], "/"), args[1])
			if err != nil {
				return err
			}
			body := map[string]any{}
			for _, kv := range args[2:] {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					return fmt.Errorf("%q: KEY=VALUE", kv)
				}
				k = strings.ReplaceAll(k, "_", "-")
				switch {
				case leafLists[k] && v == "":
					body[k] = []string{}
				case leafLists[k]:
					vals := strings.Split(v, ",")
					for i := range vals {
						vals[i] = strings.TrimSpace(vals[i])
					}
					body[k] = vals
				default:
					body[k] = v
				}
			}
			at := "/api/config/candidate/" + path
			if _, _, err := request(cmd, http.MethodPatch, at, body); err != nil {
				return err
			}
			obj, _, err := request(cmd, http.MethodGet, at, nil)
			if err != nil {
				return err
			}
			return print(cmd, obj, nil)
		},
	}
	set.Flags().StringVar(&vf, "vf", "", "the virtual firewall (default: the host)")
	root.AddCommand(set)

	var confirmTimeout int
	commit := &cobra.Command{
		Use:   "commit",
		Short: "Commit the configuration; confirm it within --confirm seconds or it rolls back",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			obj, _, err := request(cmd, http.MethodPost, "/api/deploy/apply", map[string]any{"confirm_timeout": confirmTimeout})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Commit %v %v.\n", obj["commit"], obj["status"])
			if obj["status"] == "pending" {
				fmt.Fprintf(cmd.OutOrStdout(), "Run %s confirm within %d seconds.\n", root.Name(), confirmTimeout)
			}
			return nil
		},
	}
	commit.Flags().IntVar(&confirmTimeout, "confirm", 120, "seconds to confirm in (0: no confirmation)")
	root.AddCommand(commit)
	root.AddCommand(&cobra.Command{
		Use:   "cli",
		Short: "The configuration CLI, as the console admin; it reads commands from stdin when that is not a terminal",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, srv, err := load()
			if err != nil {
				return err
			}
			env, err := srv.ConsoleCLI(cmd.Context())
			if err != nil {
				return err
			}
			fd := int(os.Stdin.Fd())
			if !term.IsTerminal(fd) {
				return cli.RunScript(cmd.Context(), env, os.Stdin, os.Stdout)
			}
			old, err := term.MakeRaw(fd)
			if err != nil {
				return err
			}
			defer term.Restore(fd, old)
			tm := cli.NewTerminal(env, struct {
				io.Reader
				io.Writer
			}{os.Stdin, os.Stdout})
			resize := func() {
				if w, h, err := term.GetSize(fd); err == nil {
					tm.SetSize(w, h)
				}
			}
			resize()
			winch := make(chan os.Signal, 1)
			signal.Notify(winch, syscall.SIGWINCH)
			defer signal.Stop(winch)
			go func() {
				for range winch {
					resize()
				}
			}()
			return tm.Run(cmd.Context())
		},
	})
	for _, a := range []struct{ use, path, done string }{
		{"confirm", "/api/deploy/confirm", "Confirmed."},
		{"rollback", "/api/deploy/rollback", "Rolled back."},
	} {
		root.AddCommand(&cobra.Command{
			Use:   a.use,
			Short: strings.ToUpper(a.use[:1]) + a.use[1:] + " the commit waiting for confirmation",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				if _, _, err := request(cmd, http.MethodPost, a.path, map[string]any{}); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), a.done)
				return nil
			},
		})
	}
}
