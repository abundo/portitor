// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

import (
	"fmt"
	"strings"
)

// token is a word of a command line. Brackets and braces stand alone
// unless quoted.
type token struct {
	text   string
	quoted bool
}

func (t token) is(s string) bool { return !t.quoted && t.text == s }

// lex splits a line into words: "double" quotes with \ escapes, 'single'
// quotes as they are, # starts a comment, and [ ] { } | are words of their
// own. open reports a quote left open (for completion).
func lex(line string) (toks []token, open bool, err error) {
	var cur strings.Builder
	inWord, quoted := false, false
	flush := func() {
		if inWord {
			toks = append(toks, token{cur.String(), quoted})
		}
		cur.Reset()
		inWord, quoted = false, false
	}
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == ' ' || r == '\t' || r == '\r' || r == '\n':
			flush()
		case r == '#' && !inWord:
			flush()
			return toks, false, nil
		case (r == '[' || r == ']' || r == '{' || r == '}' || r == '|') && !inWord:
			toks = append(toks, token{text: string(r)})
		case (r == ']' || r == '}') && inWord && !quoted:
			flush()
			toks = append(toks, token{text: string(r)})
		case r == '"':
			inWord, quoted = true, true
			closed := false
			for i++; i < len(rs); i++ {
				if rs[i] == '\\' && i+1 < len(rs) {
					i++
					cur.WriteRune(rs[i])
					continue
				}
				if rs[i] == '"' {
					closed = true
					break
				}
				cur.WriteRune(rs[i])
			}
			if !closed {
				toks = append(toks, token{cur.String(), true})
				return toks, true, fmt.Errorf("a quote is not closed")
			}
		case r == '\'':
			inWord, quoted = true, true
			closed := false
			for i++; i < len(rs); i++ {
				if rs[i] == '\'' {
					closed = true
					break
				}
				cur.WriteRune(rs[i])
			}
			if !closed {
				toks = append(toks, token{cur.String(), true})
				return toks, true, fmt.Errorf("a quote is not closed")
			}
		default:
			inWord = true
			cur.WriteRune(r)
		}
	}
	flush()
	return toks, false, nil
}
