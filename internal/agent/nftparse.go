// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// maxNftablesImport bounds the file an import reads.
const maxNftablesImport = 1 << 20

// nftInclude finds include statements, which would read files on the
// firewall.
var nftInclude = regexp.MustCompile(`(?m)^\s*include\b`)

// nftParseScript loads the file from stdin into a new, empty network
// namespace and lists it there: as JSON, then as text with handles, split
// by a line the JSON can't hold. The namespace goes away with the shell.
const nftParseScript = `nft -f - && nft -j list ruleset && echo && echo "` + nftSplit + `" && nft -a list ruleset`

const nftSplit = "#### portitor text ####"

// ParseNftables reads an nftables file for an import, the way nft does:
// variables resolved, syntax checked. Nothing is loaded on the firewall
// itself.
func (a *Agent) ParseNftables(ctx context.Context, text string) (*ParseNftablesResult, error) {
	if len(text) > maxNftablesImport {
		return nil, errors.New("the file is larger than 1 MiB")
	}
	if nftInclude.MatchString(text) {
		return nil, errors.New("include statements are not supported; paste the included files in their place")
	}
	out, err := a.run.RunInput(ctx, "", []byte(text), "unshare", "--net", "--", "sh", "-c", nftParseScript)
	if err != nil {
		// Only nft's own messages: the command line says nothing useful.
		if _, msg, ok := strings.Cut(err.Error(), "exit status "); ok {
			if _, msg, ok = strings.Cut(msg, ": "); ok {
				return nil, errors.New(strings.ReplaceAll(msg, "/dev/stdin:", "line "))
			}
		}
		return nil, err
	}
	js, txt, ok := strings.Cut(string(out), "\n"+nftSplit+"\n")
	if !ok || !json.Valid([]byte(strings.TrimSpace(js))) {
		return nil, errors.New("nft did not list the ruleset")
	}
	return &ParseNftablesResult{JSON: json.RawMessage(strings.TrimSpace(js)), Text: txt}, nil
}
