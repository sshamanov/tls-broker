// Command tls-broker is the central TLS broker / ACME proxy daemon.
//
// This is the skeleton entry point: it only reports its version. The real
// start-up (configuration, wiring, HTTP server) is written with internal/app.
package main

import (
	"fmt"

	"tls-broker/internal/version"
)

func main() {
	fmt.Println("tls-broker", version.String())
}
