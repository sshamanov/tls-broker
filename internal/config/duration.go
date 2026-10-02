package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration written in YAML as a string with units: "90s",
// "5m", "1h30m", "36h", and "d" for days ("7d", "1d12h"). A bare number is
// rejected, except "0".
type Duration time.Duration

var dayRe = regexp.MustCompile(`^(\d+)d(.*)$`)

// ParseDuration parses the YAML duration syntax.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "0" {
		return 0, nil
	}
	var days time.Duration
	if m := dayRe.FindStringSubmatch(s); m != nil {
		n, err := strconv.ParseInt(m[1], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		days = time.Duration(n) * 24 * time.Hour
		s = m[2]
		if s == "" {
			return days, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (use units such as 30s, 5m, 2h, 7d)", s)
	}
	return days + d, nil
}

// FormatDuration renders d in the shortest human form that ParseDuration
// reads back exactly: "1d12h", "90s", "2m", "1h30m", "250ms".
func FormatDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	if d < 0 {
		return "-" + FormatDuration(-d)
	}
	if d%time.Millisecond != 0 {
		return d.String()
	}
	var b strings.Builder
	if days := d / (24 * time.Hour); days > 0 {
		fmt.Fprintf(&b, "%dd", days)
		d -= days * 24 * time.Hour
	}
	if h := d / time.Hour; h > 0 {
		fmt.Fprintf(&b, "%dh", h)
		d -= h * time.Hour
	}
	if m := d / time.Minute; m > 0 {
		fmt.Fprintf(&b, "%dm", m)
		d -= m * time.Minute
	}
	if s := d / time.Second; s > 0 {
		fmt.Fprintf(&b, "%ds", s)
		d -= s * time.Second
	}
	if d > 0 {
		fmt.Fprintf(&b, "%dms", d/time.Millisecond)
	}
	return b.String()
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag == "!!int" && n.Value != "0" || n.Tag == "!!float" {
		return fmt.Errorf("line %d: duration needs a unit, for example \"30s\" or \"2h\"", n.Line)
	}
	v, err := ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %v", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return FormatDuration(time.Duration(d)), nil }
