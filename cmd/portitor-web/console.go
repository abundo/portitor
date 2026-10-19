// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

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
		Short: "Change fields of a row found by name (e.g. set interfaces ens19 addresses=192.168.1.1/24)",
		Long: "RESOURCE is an API collection (interfaces, rules, routes, instances, objects, ...). The row " +
			"is found by its name in the virtual firewall --vf (default: the host). A list field takes " +
			"comma-separated values (empty: none); numbers and true/false are converted. Commit after.",
		Args: cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, name := strings.Trim(args[0], "/"), args[1]
			_, instances, err := request(cmd, http.MethodGet, "/api/instances", nil)
			if err != nil {
				return err
			}
			var instID any
			for _, in := range instances {
				if (vf == "" && in["is_default"] == true) || (vf != "" && in["name"] == vf) {
					instID = in["id"]
				}
			}
			if instID == nil {
				return fmt.Errorf("no virtual firewall %q", vf)
			}
			path := "/api/" + res
			_, rows, err := request(cmd, http.MethodGet, path, nil)
			if err != nil {
				return err
			}
			var row map[string]any
			for _, r := range rows {
				if r["name"] != name && r["username"] != name {
					continue
				}
				if id, ok := r["instance_id"]; ok && id != instID {
					continue
				}
				row = r
			}
			if row == nil {
				return fmt.Errorf("no %s named %q", res, name)
			}
			body := map[string]any{}
			for _, kv := range args[2:] {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					return fmt.Errorf("%q: KEY=VALUE", kv)
				}
				old, known := row[k]
				if !known {
					return fmt.Errorf("%s has no field %q", res, k)
				}
				body[k] = convert(old, v)
			}
			obj, _, err := request(cmd, http.MethodPut, fmt.Sprintf("%s/%v", path, row["id"]), body)
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

// convert turns v into the type of the field's current value old.
func convert(old any, v string) any {
	switch old.(type) {
	case []any:
		out := []string{}
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	case bool:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return v
		}
		return b
	case float64:
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n
		}
	case nil:
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n
		}
		if v == "" {
			return nil
		}
	}
	return v
}
