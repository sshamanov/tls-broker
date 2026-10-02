package config

import (
	"fmt"
	"strings"
)

// Problem is one validation finding. Path is the YAML field path
// ("providers[1].directory_url", "ldap.user_filter") or the environment
// variable name for environment problems; it is empty for problems that
// belong to no field.
type Problem struct {
	Path    string
	Message string
}

// String renders "path: message".
func (p Problem) String() string {
	if p.Path == "" {
		return p.Message
	}
	return p.Path + ": " + p.Message
}

// Problems is a list of findings. A non-empty Problems is an error.
type Problems []Problem

// Error implements error.
func (ps Problems) Error() string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, "; ")
}

// Strings renders every problem as "path: message".
func (ps Problems) Strings() []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// Err returns ps as an error, or nil when it is empty.
func (ps Problems) Err() error {
	if len(ps) == 0 {
		return nil
	}
	return ps
}

// collector accumulates problems and warnings during validation.
type collector struct {
	problems Problems
	warnings Problems
}

func (c *collector) errf(path, format string, args ...any) {
	c.problems = append(c.problems, Problem{Path: path, Message: fmt.Sprintf(format, args...)})
}

func (c *collector) warnf(path, format string, args ...any) {
	c.warnings = append(c.warnings, Problem{Path: path, Message: fmt.Sprintf(format, args...)})
}
