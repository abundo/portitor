// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package netconf

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// eom ends a message in NETCONF 1.0's framing (RFC 6242 section 4.3).
const eom = "]]>]]>"

// maxMessage caps a message's size.
const maxMessage = 64 << 20

// framer reads and writes messages: end-of-message framing until both
// sides speak base:1.1, chunked framing after (RFC 6242 section 4.2).
type framer struct {
	r       *bufio.Reader
	w       io.Writer
	chunked bool
}

func newFramer(rw io.ReadWriter) *framer {
	return &framer{r: bufio.NewReaderSize(rw, 64<<10), w: rw}
}

func (f *framer) read() ([]byte, error) {
	if f.chunked {
		return f.readChunked()
	}
	var msg []byte
	for {
		b, err := f.r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(bytes.TrimSpace(msg)) > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		msg = append(msg, b)
		if bytes.HasSuffix(msg, []byte(eom)) {
			return msg[:len(msg)-len(eom)], nil
		}
		if len(msg) > maxMessage {
			return nil, errors.New("message too large")
		}
	}
}

func (f *framer) readChunked() ([]byte, error) {
	var msg []byte
	for {
		// \n#<size>\n or \n##\n
		if err := f.expect('\n'); err != nil {
			return nil, err
		}
		if err := f.expect('#'); err != nil {
			return nil, err
		}
		b, err := f.r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '#' {
			if err := f.expect('\n'); err != nil {
				return nil, err
			}
			return msg, nil
		}
		digits := []byte{b}
		for {
			b, err := f.r.ReadByte()
			if err != nil {
				return nil, err
			}
			if b == '\n' {
				break
			}
			digits = append(digits, b)
			if len(digits) > 10 {
				return nil, errors.New("bad chunk size")
			}
		}
		n, err := strconv.Atoi(string(digits))
		if err != nil || n < 1 || len(msg)+n > maxMessage {
			return nil, fmt.Errorf("bad chunk size %q", digits)
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(f.r, chunk); err != nil {
			return nil, err
		}
		msg = append(msg, chunk...)
	}
}

func (f *framer) expect(c byte) error {
	b, err := f.r.ReadByte()
	if err != nil {
		return err
	}
	if b != c {
		return fmt.Errorf("bad framing: %q, not %q", b, c)
	}
	return nil
}

func (f *framer) write(msg []byte) error {
	if f.chunked {
		if _, err := fmt.Fprintf(f.w, "\n#%d\n", len(msg)); err != nil {
			return err
		}
		if _, err := f.w.Write(msg); err != nil {
			return err
		}
		_, err := io.WriteString(f.w, "\n##\n")
		return err
	}
	if _, err := f.w.Write(msg); err != nil {
		return err
	}
	_, err := io.WriteString(f.w, eom)
	return err
}
