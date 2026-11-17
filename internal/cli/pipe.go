// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/abundo/portitor/internal/datastore"
)

// stage is one filter after a "|": grep or wc.
type stage struct {
	wc     string // wc: the counts to show, of "lwmc"; "" for grep
	re     *regexp.Regexp
	invert bool
	before int // grep -B: lines of context before a match
	after  int // grep -A: lines of context after a match
}

// apply gives what the stage makes of text.
func (st stage) apply(text string) string {
	if st.wc != "" {
		return st.count(text)
	}
	lines := strings.SplitAfter(text, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	match := make([]bool, len(lines))
	for i, l := range lines {
		match[i] = st.re.MatchString(strings.TrimSuffix(l, "\n")) != st.invert
	}
	var b strings.Builder
	last, until := -1, -1 // the last line written; context runs to until
	for i, l := range lines {
		show := match[i] || i <= until
		if !show {
			for j := i + 1; j <= i+st.before && j < len(lines); j++ {
				if match[j] {
					show = true
					break
				}
			}
		}
		if !show {
			continue
		}
		if last >= 0 && i > last+1 && (st.before > 0 || st.after > 0) {
			b.WriteString("--\n")
		}
		b.WriteString(l)
		if !strings.HasSuffix(l, "\n") {
			b.WriteString("\n")
		}
		last = i
		if match[i] {
			until = i + st.after
		}
	}
	return b.String()
}

// count gives wc's counts of text: lines, words, characters, bytes, in that
// order, those st.wc asks for.
func (st stage) count(text string) string {
	n := map[rune]int{
		'l': strings.Count(text, "\n"),
		'w': len(strings.Fields(text)),
		'm': utf8.RuneCountInString(text),
		'c': len(text),
	}
	var parts []string
	for _, k := range "lwmc" {
		if strings.ContainsRune(st.wc, k) {
			parts = append(parts, strconv.Itoa(n[k]))
		}
	}
	if len(parts) == 1 {
		return parts[0] + "\n"
	}
	for i, p := range parts {
		parts[i] = fmt.Sprintf("%7s", p)
	}
	return strings.Join(parts, " ") + "\n"
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

const pipeHelp = "after | only grep [-iEFvwx] [-A n] [-B n] [-C n] <pattern> and wc [-lwmc] are known"

func parseStage(g []token) (stage, error) {
	switch {
	case len(g) > 0 && g[0].is("grep"):
		return parseGrep(g[1:])
	case len(g) > 0 && g[0].is("wc"):
		return parseWC(g[1:])
	}
	return stage{}, errors.New(pipeHelp)
}

func parseWC(args []token) (stage, error) {
	var st stage
	for _, a := range args {
		if a.quoted || !strings.HasPrefix(a.text, "-") || len(a.text) < 2 {
			return st, fmt.Errorf("wc: %q: only options (-l, -w, -m, -c)", a.text)
		}
		for _, f := range a.text[1:] {
			if !strings.ContainsRune("lwmc", f) {
				return st, fmt.Errorf("wc: unknown option -%c (-l, -w, -m, -c)", f)
			}
			st.wc += string(f)
		}
	}
	if st.wc == "" {
		st.wc = "lwc"
	}
	return st, nil
}

func parseGrep(args []token) (stage, error) {
	var st stage
	var icase, fixed, word, line bool
	// number reads the count of -A, -B or -C: the rest of the word, or the next
	number := func(f rune, rest string) (int, error) {
		if rest == "" {
			if len(args) < 2 {
				return 0, fmt.Errorf("grep: -%c needs a number", f)
			}
			rest = args[1].text
			args = args[1:]
		}
		n, err := strconv.Atoi(rest)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("grep: -%c %q: not a number", f, rest)
		}
		return n, nil
	}
	for len(args) > 0 && !args[0].quoted && strings.HasPrefix(args[0].text, "-") && len(args[0].text) > 1 {
		if args[0].text == "--" {
			args = args[1:]
			break
		}
		flags := args[0].text[1:]
	flagLoop:
		for i, f := range flags {
			switch f {
			case 'i':
				icase = true
			case 'v':
				st.invert = true
			case 'E':
				// Go's regular expressions are extended ones already
			case 'F':
				fixed = true
			case 'w':
				word = true
			case 'x':
				line = true
			case 'A', 'B', 'C':
				n, err := number(f, flags[i+1:])
				if err != nil {
					return st, err
				}
				if f != 'B' {
					st.after = n
				}
				if f != 'A' {
					st.before = n
				}
				break flagLoop
			default:
				return st, fmt.Errorf("grep: unknown option -%c (-i, -v, -E, -F, -w, -x, -A n, -B n, -C n)", f)
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
	if fixed {
		pat = regexp.QuoteMeta(pat)
	}
	switch {
	case line:
		pat = "^(?:" + pat + ")$"
	case word:
		pat = `(?:^|\W)(?:` + pat + `)(?:\W|$)`
	}
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
