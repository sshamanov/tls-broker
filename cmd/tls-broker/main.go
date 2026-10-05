// Command tls-broker is the central TLS broker / ACME proxy daemon.
//
// Without arguments (or with "serve") it runs the broker until SIGTERM or
// SIGINT. The other subcommands are maintenance tools that work on the data
// directory named by TLS_BROKER_DATA_DIR, usable inside the container with
// "docker compose exec tls-broker tls-broker ...":
//
//	tls-broker [serve]
//	tls-broker version | --version
//	tls-broker healthcheck
//	tls-broker backup <dest.db>
//	tls-broker config validate <file.yaml>
//	tls-broker config apply <file.yaml>
//	tls-broker user set-role [--local] <name> <normal|wildcard_allowed|admin>
//	tls-broker user block|unblock [--local] <name>
//	tls-broker docs publish [--dry-run] [--prune] [--out dir] [--docs dir] [--broker-url url]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"tls-broker/internal/app"
	"tls-broker/internal/config"
	"tls-broker/internal/core"
	"tls-broker/internal/version"
)

const usage = `usage:
  tls-broker [serve]                        run the broker
  tls-broker version | --version            print the version
  tls-broker healthcheck                    exit 0 when /healthz answers 200
  tls-broker backup <dest.db>               consistent SQLite snapshot (VACUUM INTO)
  tls-broker config validate <file.yaml>    check a configuration file
  tls-broker config apply <file.yaml>       activate it as the next generation (restart to use)
  tls-broker user set-role [--local] <name> <normal|wildcard_allowed|admin>
  tls-broker user block [--local] <name>
  tls-broker user unblock [--local] <name>
  tls-broker docs publish [--dry-run] [--prune] [--out dir] [--docs dir] [--broker-url url]
                                            copy the user guide to Confluence (TLS_BROKER_CONFLUENCE_*)

Settings come from the TLS_BROKER_* environment variables (docs/configuration.md).
`

// errUsage marks a command-line mistake (exit status 2).
var errUsage = errors.New("usage")

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && (args[0] == "version" || args[0] == "--version" || args[0] == "-version") {
		fmt.Fprintln(stdout, "tls-broker", version.String())
		return 0
	}
	if len(args) > 0 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(stdout, usage)
		return 0
	}
	env, probs := config.LoadEnv(os.LookupEnv)
	if len(probs) > 0 {
		fmt.Fprintln(stderr, "invalid environment:")
		for _, p := range probs {
			fmt.Fprintln(stderr, "  "+p.String())
		}
		return 1
	}
	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: env.LogLevel}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	err := dispatch(ctx, env, log, args, stdout)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		fmt.Fprintf(stderr, "%v\n\n%s", err, usage)
		return 2
	default:
		fmt.Fprintln(stderr, "tls-broker:", err)
		return 1
	}
}

func dispatch(ctx context.Context, env config.Env, log *slog.Logger, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "serve" {
		if len(args) > 1 {
			return fmt.Errorf("%w: serve takes no arguments", errUsage)
		}
		return serve(ctx, env, log)
	}
	switch args[0] {
	case "healthcheck":
		return app.HealthCheck(ctx, env)
	case "backup":
		if len(args) != 2 {
			return fmt.Errorf("%w: backup <dest.db>", errUsage)
		}
		return app.Backup(ctx, env, args[1], out)
	case "config":
		if len(args) != 3 {
			return fmt.Errorf("%w: config validate|apply <file.yaml>", errUsage)
		}
		switch args[1] {
		case "validate":
			return app.ConfigValidate(ctx, env, args[2], out)
		case "apply":
			return app.ConfigApply(ctx, env, args[2], out, log)
		}
		return fmt.Errorf("%w: unknown config command %q", errUsage, args[1])
	case "user":
		return user(ctx, env, args[1:], out)
	case "docs":
		return docs(ctx, env, args[1:], out)
	}
	return fmt.Errorf("%w: unknown command %q", errUsage, args[0])
}

func user(ctx context.Context, env config.Env, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: user set-role|block|unblock", errUsage)
	}
	cmd, rest := args[0], args[1:]
	local := slices.Contains(rest, "--local")
	rest = slices.DeleteFunc(slices.Clone(rest), func(s string) bool { return s == "--local" })
	switch cmd {
	case "set-role":
		if len(rest) != 2 {
			return fmt.Errorf("%w: user set-role [--local] <name> <role>", errUsage)
		}
		return app.SetRole(ctx, env, rest[0], local, core.Role(rest[1]), out)
	case "block", "unblock":
		if len(rest) != 1 {
			return fmt.Errorf("%w: user %s [--local] <name>", errUsage, cmd)
		}
		return app.SetBlocked(ctx, env, rest[0], local, cmd == "block", out)
	}
	return fmt.Errorf("%w: unknown user command %q", errUsage, cmd)
}

func docs(ctx context.Context, env config.Env, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "publish" {
		return fmt.Errorf("%w: docs publish [--dry-run] [--prune] [--out dir] [--docs dir] [--broker-url url]", errUsage)
	}
	fs := flag.NewFlagSet("docs publish", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := app.DocsOptions{Lookup: os.LookupEnv}
	fs.BoolVar(&o.DryRun, "dry-run", false, "only read Confluence and print what would change")
	fs.BoolVar(&o.Prune, "prune", false, "delete the root's obsolete child pages titled \""+app.ObsoleteTitlePrefix+"...\"")
	fs.StringVar(&o.OutDir, "out", "", "also write the storage-format XHTML to this directory (guide.xhtml)")
	fs.StringVar(&o.Dir, "docs", "", "directory holding guide.md (default: the image's copy)")
	fs.StringVar(&o.BrokerURL, "broker-url", "", "broker URL for the examples (default: server.external_url)")
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("%w: docs publish: %v", errUsage, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: docs publish takes no arguments, got %q", errUsage, fs.Args())
	}
	return app.DocsPublish(ctx, env, o, out)
}

func serve(ctx context.Context, env config.Env, log *slog.Logger) error {
	a, err := app.New(ctx, env, app.Options{Logger: log})
	if err != nil {
		return err
	}
	return a.Run(ctx)
}
