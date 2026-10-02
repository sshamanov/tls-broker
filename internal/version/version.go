// Package version carries build information.
package version

// Version is the build version. It is set at link time with
//
//	-ldflags "-X tls-broker/internal/version.Version=<value>"
//
// and stays "dev" for plain `go build` and `go test`.
var Version = "dev"

// String returns the version for display, never empty.
func String() string {
	if Version == "" {
		return "dev"
	}
	return Version
}
