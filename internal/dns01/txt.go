package dns01

import (
	"errors"
	"fmt"
	"strings"
)

// maxCharString is the longest DNS character-string (RFC 1035 §3.3).
const maxCharString = 255

// maxValueLen bounds a challenge value. ACME dns-01 values are 43 characters
// (base64url SHA-256); the bound only keeps odd DNS-proxy input sane.
const maxValueLen = 1024

// ErrInvalidValue is returned by Present for a TXT value that is empty, too
// long or not printable ASCII. Nothing is created.
var ErrInvalidValue = errors.New("invalid TXT value")

// checkValue validates a challenge value before anything is recorded.
func checkValue(v string) error {
	if v == "" || len(v) > maxValueLen {
		return fmt.Errorf("%w: length %d", ErrInvalidValue, len(v))
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return fmt.Errorf("%w: byte 0x%02x at %d", ErrInvalidValue, v[i], i)
		}
	}
	return nil
}

// QuoteTXT renders one TXT value in Route53 presentation format: one or more
// double-quoted character-strings of at most 255 bytes, separated by spaces,
// with '"' and '\' escaped.
func QuoteTXT(v string) string {
	var b strings.Builder
	for first := true; first || v != ""; first = false {
		n := min(len(v), maxCharString)
		chunk := v[:n]
		v = v[n:]
		if !first {
			b.WriteByte(' ')
		}
		b.WriteByte('"')
		for i := 0; i < len(chunk); i++ {
			if c := chunk[i]; c == '"' || c == '\\' {
				b.WriteByte('\\')
			}
			b.WriteByte(chunk[i])
		}
		b.WriteByte('"')
	}
	return b.String()
}

// UnquoteTXT parses one Route53 TXT value (one or more quoted
// character-strings, or a single unquoted word) and returns the strings
// concatenated, which is what a resolver returns for the record. Escapes
// are decoded as in RFC 1035 master format, which is what Route53 returns:
// "\X" stands for X, and "\DDD" is one byte given as exactly three octal
// digits (\052 is '*'). A backslash followed by a digit that is not such an
// escape is malformed.
func UnquoteTXT(s string) (string, error) {
	var out strings.Builder
	i := 0
	parsed := false
	for {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i == len(s) {
			break
		}
		quoted := s[i] == '"'
		if quoted {
			i++
		}
		for {
			if i == len(s) {
				if quoted {
					return "", fmt.Errorf("unterminated TXT string %q", s)
				}
				break
			}
			c := s[i]
			if quoted && c == '"' {
				i++
				break
			}
			if !quoted && c == ' ' {
				break
			}
			if c == '\\' {
				if i+1 >= len(s) {
					return "", fmt.Errorf("dangling escape in TXT string %q", s)
				}
				if isDigit(s[i+1]) {
					if i+3 >= len(s) || !isOctal(s[i+1]) || !isOctal(s[i+2]) || !isOctal(s[i+3]) {
						return "", fmt.Errorf("bad escape in TXT string %q", s)
					}
					n := int(s[i+1]-'0')*64 + int(s[i+2]-'0')*8 + int(s[i+3]-'0')
					if n > 255 {
						return "", fmt.Errorf("bad escape in TXT string %q", s)
					}
					out.WriteByte(byte(n))
					i += 4
					continue
				}
				out.WriteByte(s[i+1])
				i += 2
				continue
			}
			out.WriteByte(c)
			i++
		}
		parsed = true
	}
	if !parsed {
		return "", fmt.Errorf("empty TXT value")
	}
	return out.String(), nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isOctal(c byte) bool { return c >= '0' && c <= '7' }
