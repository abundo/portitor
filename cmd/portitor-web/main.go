// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// portitor-web is the portal to the firewalls' GUIs, with no database of
// its own, and the witness of HA pairs. Run as "portitor-config" (a
// symlink) it is portitor-config: the firewall's own configuration, its
// database, GUI and API, on the firewall. See AGENTS.md.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
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
	root := portalCommand()
	if filepath.Base(os.Args[0]) == "portitor-config" {
		root = configCommand()
	}
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

// setLogging sets the log level of every command.
func setLogging(debug *bool) func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		level := slog.LevelInfo
		if *debug {
			level = slog.LevelDebug
		}
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	}
}

// configCommand is portitor-config's.
func configCommand() *cobra.Command {
	var configFile, bind string
	var debug bool
	root := &cobra.Command{
		Use:              "portitor-config",
		Short:            "Portitor: the firewall's configuration, GUI and API",
		SilenceUsage:     true,
		SilenceErrors:    true,
		Version:          buildinfo.Version,
		PersistentPreRun: setLogging(&debug),
	}
	root.PersistentFlags().StringVarP(&configFile, "config", "f", web.DefaultLocalConfigFile, "config file")
	root.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "debug logging")

	load := func() (*web.Config, *web.Server, error) {
		cfg, err := web.LoadConfig(configFile)
		if err != nil {
			return nil, nil, err
		}
		cfg.Local = true
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
		Use:   "reset-2fa <username>",
		Short: "Turn off a user's two-factor login (a lost phone and recovery codes)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, srv, err := load()
			if err != nil {
				return err
			}
			if err := web.ResetTOTP(srv, args[0]); err != nil {
				return err
			}
			fmt.Println("two-factor login of", args[0], "turned off")
			return nil
		},
	})

	addConsoleCommands(root, load)

	var agentURL, agentTokenFile, agentFingerprint string
	setAgent := &cobra.Command{
		Use:   "set-agent",
		Short: "Set the first firewall's agent (portitor-config: its own agent)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, srv, err := load()
			if err != nil {
				return err
			}
			var tok []byte
			if agentTokenFile == "-" {
				tok, err = io.ReadAll(os.Stdin)
			} else {
				tok, err = os.ReadFile(agentTokenFile)
			}
			if err != nil {
				return err
			}
			return web.SetAgent(srv, agentURL, strings.TrimSpace(string(tok)), agentFingerprint)
		},
	}
	setAgent.Flags().StringVar(&agentURL, "url", "https://127.0.0.1:8443", "agent API")
	setAgent.Flags().StringVar(&agentTokenFile, "token-file", "/etc/portitor/agent.token", "agent token file (-: standard input)")
	setAgent.Flags().StringVar(&agentFingerprint, "fingerprint", "", "agent certificate SHA-256")
	root.AddCommand(setAgent)

	var importName string
	importVF := &cobra.Command{
		Use:   "import-vf <bundle.json>",
		Short: "Add a virtual firewall from a bundle; into a new database, the host's configuration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, srv, err := load()
			if err != nil {
				return err
			}
			problems, err := web.ImportBundleFile(cmd.Context(), srv, args[0], importName)
			if err != nil {
				return err
			}
			for _, p := range problems {
				fmt.Fprintln(cmd.ErrOrStderr(), "problem:", p)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "imported")
			return nil
		},
	}
	importVF.Flags().StringVar(&importName, "name", "", "its name here (default: the bundle's)")
	root.AddCommand(importVF)

	var allAgents bool
	agentURLCmd := &cobra.Command{
		Use:   "agent-url",
		Short: "Print the first firewall's agent URL, or with --all every firewall's, one per line (install.py updates those hosts)",
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
			q := db.Model(&models.Firewall{}).Order("id")
			if !allAgents {
				q = q.Limit(1)
			}
			var urls []string
			if err := q.Pluck("agent_url", &urls).Error; err != nil {
				return err
			}
			for _, u := range urls {
				fmt.Println(u)
			}
			return nil
		},
	}
	agentURLCmd.Flags().BoolVar(&allAgents, "all", false, "every firewall's agent URL")
	root.AddCommand(agentURLCmd)

	var bo web.BootstrapOptions
	var tokenFile, address, wanAddress, gateway, dhcpRange, dhcpDNS, defaultRoute string
	bootstrap := &cobra.Command{
		Use:   "bootstrap",
		Short: "Configure and deploy this new firewall (the installer ISO's first boot)",
		Long: `Stores the agent settings, configures the LAN interface with its address
(or DHCP, without a default route when there is a WAN, unless
--default-route lan with a DHCP WAN, which then takes none), the WAN interface
(static or DHCP) and the default route, describes them as LAN and WAN,
accepts the GUI port, SSH and ping from the LAN and forwarding from the LAN
to the WAN, masquerades on the WAN, serves --dhcp-range on the static LAN
(if given), and deploys.
Every other interface of the firewall is imported as it is. Refused once
anything has been deployed, unless --reconfigure (portitor-setup run again):
then the LAN and WAN get exactly these settings, the IPv4 default route is
--gateway or none, the GUI, SSH and ping rules are enabled on the LAN, the
forward and masquerade rules move to the new LAN and WAN, and the agent
settings are kept unless --agent-fingerprint is given.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, srv, err := load()
			if err != nil {
				return err
			}
			if bo.LAN == "" || address == "" {
				return fmt.Errorf("--lan and --address are required")
			}
			if bo.AgentFingerprint != "" {
				var tok []byte
				if tokenFile == "-" {
					// The inherited stdin: another user can't reopen root's
					// pipe through /dev/stdin.
					tok, err = io.ReadAll(os.Stdin)
				} else {
					tok, err = os.ReadFile(tokenFile)
				}
				if err != nil {
					return err
				}
				bo.AgentToken = strings.TrimSpace(string(tok))
			}
			if address != "dhcp" {
				if bo.Address, err = netip.ParsePrefix(address); err != nil {
					return fmt.Errorf("--address: %w", err)
				}
			}
			if wanAddress != "" {
				if bo.WANAddress, err = netip.ParsePrefix(wanAddress); err != nil {
					return fmt.Errorf("--wan-address: %w", err)
				}
			}
			switch defaultRoute {
			case "wan":
			case "lan":
				bo.DefaultRouteLAN = true
			default:
				return fmt.Errorf("--default-route: lan or wan, not %q", defaultRoute)
			}
			if gateway != "" {
				if bo.Gateway, err = netip.ParseAddr(gateway); err != nil {
					return fmt.Errorf("--gateway: %w", err)
				}
			}
			if dhcpRange != "" {
				if bo.DHCPStart, bo.DHCPEnd, err = web.ParseDHCPRange(dhcpRange); err != nil {
					return fmt.Errorf("--dhcp-range: %w", err)
				}
			}
			for _, d := range strings.FieldsFunc(dhcpDNS, func(r rune) bool { return r == ',' || r == ' ' }) {
				ip, err := netip.ParseAddr(d)
				if err != nil {
					return fmt.Errorf("--dhcp-dns: %w", err)
				}
				bo.DHCPDNS = append(bo.DHCPDNS, ip)
			}
			return printDeployment(web.Bootstrap(cmd.Context(), srv, bo))
		},
	}
	bf := bootstrap.Flags()
	bf.StringVar(&bo.AgentURL, "agent-url", "https://127.0.0.1:8443", "agent API")
	bf.StringVar(&tokenFile, "agent-token-file", "/etc/portitor/agent.token", "agent token file, - for stdin")
	bf.StringVar(&bo.AgentFingerprint, "agent-fingerprint", "", "agent certificate SHA-256 (from portitor-agent init)")
	bf.StringVar(&bo.LAN, "lan", "", "LAN interface")
	bf.StringVar(&address, "address", "", "LAN address with prefix length, e.g. 192.168.1.1/24, or dhcp")
	bf.StringVar(&bo.WAN, "wan", "", "WAN interface (optional)")
	bf.StringVar(&wanAddress, "wan-address", "", "static WAN address with prefix length (default: DHCP)")
	bf.StringVar(&gateway, "gateway", "", "default gateway (optional; on the WAN if it is static, else on the static LAN)")
	bf.StringVar(&defaultRoute, "default-route", "wan", "which DHCP interface takes the default route when both the LAN and the WAN use DHCP: lan or wan")
	bf.StringVar(&dhcpRange, "dhcp-range", "", "DHCP server on the static LAN, e.g. 192.168.1.100-192.168.1.199 (optional)")
	bf.StringVar(&dhcpDNS, "dhcp-dns", "", "DNS servers DHCP hands out, comma separated (default: the firewall, if its DNS listens on the LAN)")
	bf.IntVar(&bo.GUIPort, "gui-port", 443, "port to open for the GUI on the LAN, 0 for none")
	bf.BoolVar(&bo.Reconfigure, "reconfigure", false, "change the LAN and WAN of a deployed installation")
	root.AddCommand(bootstrap)

	root.AddCommand(&cobra.Command{
		Use:   "fingerprint",
		Short: "Print the SHA-256 fingerprint of tls_cert, which portitor-web and the HA peer pin",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := web.LoadConfig(configFile)
			if err != nil {
				return err
			}
			fp, err := web.CertFingerprint(cfg.TLSCert)
			if err != nil {
				return err
			}
			fmt.Println(fp)
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "witness-string",
		Short: "Print the HA pair's witness string, for its external witness (portitor-web's web.yaml)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, srv, err := load()
			if err != nil {
				return err
			}
			str, err := web.WitnessString(srv)
			if err != nil {
				return err
			}
			fmt.Println(str)
			return nil
		},
	})

	var force bool
	promote := &cobra.Command{
		Use:   "promote",
		Short: "Make this HA secondary the primary, its primary lost, and commit",
		Long: `Run on the HA secondary whose primary is lost. Its copy of the
configuration becomes the pair's: the instances and tasks move to it, with
the two hosts' values swapped (addresses and peer addresses, router ids,
NETs, VRRP priorities), the old primary becomes the secondary, and it commits.
The old primary, back, stays fenced until this host catches it up.
Refused while this host's agent hears the primary, unless --force.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, srv, err := load()
			if err != nil {
				return err
			}
			res, err := web.PromoteHere(cmd.Context(), srv, force)
			if res != nil {
				for _, d := range res.Deployments {
					fmt.Printf("%d %s %s\n", d.FirewallID, d.Status, d.Message)
				}
			}
			if err != nil {
				return err
			}
			fmt.Println("promoted: this host is the primary, commit", res.Commit)
			return nil
		},
	}
	promote.Flags().BoolVar(&force, "force", false, "promote even though the agent hears the primary")
	root.AddCommand(promote)
	return root
}

// printDeployment prints a bootstrap's result.
func printDeployment(dep *models.Deployment, err error) error {
	if dep != nil && dep.Log != "" {
		fmt.Println(dep.Log)
	}
	if err != nil {
		return err
	}
	fmt.Println("deployed generation", dep.Generation)
	return nil
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
