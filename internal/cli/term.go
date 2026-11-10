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
	"sync"
	"unicode/utf8"

	"golang.org/x/term"
)

// Terminal is a session on an interactive terminal (a console's, or an
// SSH session's with a pty).
type Terminal struct {
	t  *term.Terminal
	s  *Session
	rw io.ReadWriter // the raw terminal, for the pager's key and prompt

	mu            sync.Mutex
	width, height int
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
	tm := &Terminal{t: t, s: NewSession(env, t), rw: rw}
	tm.s.page = tm.page
	t.SetPrompt(tm.s.PromptLine())
	return tm
}

// SetSize sets the terminal's size.
func (tm *Terminal) SetSize(width, height int) {
	tm.mu.Lock()
	tm.width, tm.height = width, height
	tm.mu.Unlock()
	_ = tm.t.SetSize(width, height)
}

// page writes text a screen at a time: Space for the next screen, Enter for
// the next line, q to stop. Text that fits is written as it is.
func (tm *Terminal) page(text string) {
	tm.mu.Lock()
	width, height := tm.width, tm.height
	tm.mu.Unlock()
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	rows := func(l string) int {
		if width <= 0 {
			return 1
		}
		return max(1, (utf8.RuneCountInString(l)+width-1)/width)
	}
	total := 0
	for _, l := range lines {
		total += rows(l)
	}
	room := height - 1
	if height <= 0 || total <= room {
		tm.t.Write([]byte(text))
		return
	}
	budget := room
	var chunk strings.Builder
	flush := func() {
		if chunk.Len() > 0 {
			tm.t.Write([]byte(chunk.String()))
			chunk.Reset()
		}
	}
	for i := 0; i < len(lines); i++ {
		r := rows(lines[i])
		if budget < r && budget < room { // the screen is full
			flush()
			n := tm.more()
			if n == 0 {
				return
			}
			budget = n
		}
		chunk.WriteString(lines[i] + "\n")
		budget -= r
	}
	flush()
}

// more asks for the next screen: it answers the rows to show, 0 to stop.
func (tm *Terminal) more() int {
	tm.mu.Lock()
	room := tm.height - 1
	tm.mu.Unlock()
	io.WriteString(tm.rw, "\x1b[7m--More-- (Space: next screen, Enter: next line, q: stop)\x1b[0m")
	defer io.WriteString(tm.rw, "\r\x1b[K")
	buf := make([]byte, 1)
	for {
		if n, err := tm.rw.Read(buf); n == 0 || err != nil && n == 0 {
			return 0
		}
		switch buf[0] {
		case ' ':
			return room
		case '\r', '\n':
			return 1
		case 'q', 'Q', 3, 4:
			return 0
		}
	}
}

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
