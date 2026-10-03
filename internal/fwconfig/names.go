// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValidName checks a name that is only shown, compared and quoted, never
// parsed by another program as a word: any text without control
// characters (which could start a new line in a config file or log),
// with no space around it. Linux and other programs restrict the names of
// instances, interfaces and what goes into their configs unquoted; those
// have their own checks.
func ValidName(s string) bool {
	return s != "" && utf8.ValidString(s) && strings.TrimSpace(s) == s &&
		!strings.ContainsFunc(s, unicode.IsControl)
}

// ValidFileName checks a name that is also a file or directory name on
// the agent: a ValidName without "/", not "." or "..", and within the
// file system's 255 bytes.
func ValidFileName(s string) bool {
	return ValidName(s) && !strings.Contains(s, "/") && s != "." && s != ".." && len(s) <= 255
}

// ValidDNSTemplateName checks a DNS template or DNSSEC policy name, a
// quoted string in named.conf that dnsmgr2 writes without escaping.
func ValidDNSTemplateName(s string) bool {
	return ValidName(s) && !strings.ContainsAny(s, `"\`)
}

// ValidWord checks a name that a program reads as one word of its config
// (FRR's WORD): a ValidName without spaces, and not starting a comment
// or asking for help ("!", "#", "?").
func ValidWord(s string) bool {
	return ValidName(s) && !strings.ContainsFunc(s, unicode.IsSpace) &&
		!strings.ContainsAny(s, "?") && s[0] != '!' && s[0] != '#'
}
