// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/term"
)

// Terminal is a session on an interactive terminal (a console's, or an
// SSH session's with a pty).
type Terminal struct {
	t *term.Terminal
	s *Session
}

// ctrlC turns Ctrl-C into Ctrl-U: it clears the line instead of ending
// the session, as x/term would.
type ctrlC struct{ io.ReadWriter }

func (c ctrlC) Read(p []byte) (int, error) {
	n, err := c.ReadWriter.Read(p)
	for i := range n {
		if p[i] == 3 {
			p[i] = 21
		}
	}
	return n, err
}

// NewTerminal starts a session on rw.
func NewTerminal(env *Env, rw io.ReadWriter) *Terminal {
	t := term.NewTerminal(ctrlC{rw}, "")
	tm := &Terminal{t: t, s: NewSession(env, t)}
	t.SetPrompt(tm.s.PromptLine())
	return tm
}

// SetSize sets the terminal's size.
func (tm *Terminal) SetSize(width, height int) { _ = tm.t.SetSize(width, height) }

// inQuote reports whether line ends inside a quote.
func inQuote(line string) bool {
	_, open, _ := lex(line)
	return open
}

// Run reads and runs lines until the user logs out or the input ends.
func (tm *Terminal) Run(ctx context.Context) error {
	t, s := tm.t, tm.s
	defer s.Close()
	t.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		switch key {
		case '\t':
			newLine, items := s.Complete(ctx, line[:pos])
			if len(items) > 0 {
				go tm.above(items)
			}
			return newLine + line[pos:], len(newLine), true
		case '?':
			if inQuote(line[:pos]) {
				return "", 0, false
			}
			_, items := s.Suggest(ctx, line[:pos])
			go tm.above(items)
			return line, pos, true
		}
		return "", 0, false
	}
	fmt.Fprintf(t, "Portitor %s. Type ? for what may follow, help for the commands.\n", s.env.Version)
	for !s.Done() {
		fmt.Fprintf(t, "\n%s\n", s.Prompt())
		line, err := t.ReadLine()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil && !errors.Is(err, term.ErrPasteIndicator) {
			return err
		}
		if err := s.Exec(ctx, line); err != nil {
			fmt.Fprintf(t, "Error: %v\n", err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

// above writes the suggestions above the line being typed.
func (tm *Terminal) above(items []Item) {
	var b bytes.Buffer
	b.WriteString("\n")
	WriteHelp(&b, items)
	tm.t.Write([]byte(strings.ReplaceAll(b.String(), "\r\n", "\n")))
}

// RunScript runs the lines of r, as a session without a terminal (piped
// commands, an SSH exec). It stops at the first error.
func RunScript(ctx context.Context, env *Env, r io.Reader, w io.Writer) error {
	s := NewSession(env, w)
	defer s.Close()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	n := 0
	for sc.Scan() && !s.Done() {
		n++
		if err := s.Exec(ctx, sc.Text()); err != nil {
			return fmt.Errorf("line %d: %s: %w", n, strings.TrimSpace(sc.Text()), err)
		}
	}
	return sc.Err()
}
