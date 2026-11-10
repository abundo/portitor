// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
)

// stage is one filter after a "|": grep.
type stage struct {
	re     *regexp.Regexp
	invert bool
}

// apply keeps the lines of text the stage lets through.
func (st stage) apply(text string) string {
	var b strings.Builder
	for _, l := range strings.SplitAfter(text, "\n") {
		if l == "" {
			continue
		}
		if st.re.MatchString(strings.TrimSuffix(l, "\n")) != st.invert {
			b.WriteString(l)
		}
	}
	return b.String()
}

// splitPipe splits line at its unquoted "|" words into the command and the
// filters that follow it.
func splitPipe(line string) (string, []stage, error) {
	toks, _, err := lex(line)
	if err != nil {
		return line, nil, nil // exec reports it
	}
	var groups [][]token
	cur := []token{}
	for _, t := range toks {
		if t.is("|") {
			groups = append(groups, cur)
			cur = []token{}
			continue
		}
		cur = append(cur, t)
	}
	if len(groups) == 0 {
		return line, nil, nil
	}
	groups = append(groups, cur)
	var stages []stage
	for _, g := range groups[1:] {
		st, err := parseStage(g)
		if err != nil {
			return "", nil, err
		}
		stages = append(stages, st)
	}
	var parts []string
	for _, t := range groups[0] {
		if t.quoted {
			parts = append(parts, datastore.Quote(t.text))
		} else {
			parts = append(parts, t.text)
		}
	}
	return strings.Join(parts, " "), stages, nil
}

func parseStage(g []token) (stage, error) {
	if len(g) == 0 || !g[0].is("grep") {
		return stage{}, errors.New("after | only grep [-i] [-v] <pattern> is known")
	}
	var st stage
	icase := false
	args := g[1:]
	for len(args) > 0 && !args[0].quoted && strings.HasPrefix(args[0].text, "-") && len(args[0].text) > 1 {
		for _, f := range args[0].text[1:] {
			switch f {
			case 'i':
				icase = true
			case 'v':
				st.invert = true
			default:
				return st, fmt.Errorf("grep: unknown option -%c (-i, -v)", f)
			}
		}
		args = args[1:]
	}
	if len(args) == 0 {
		return st, errors.New("grep what?")
	}
	words := make([]string, len(args))
	for i, a := range args {
		words[i] = a.text
	}
	pat := strings.Join(words, " ")
	if icase {
		pat = "(?i)" + pat
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return st, fmt.Errorf("grep: %v", err)
	}
	st.re = re
	return st, nil
}
