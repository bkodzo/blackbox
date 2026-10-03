// Command blackbox is an audit gateway for AI agents. It forwards agent
// traffic to a model server and records every exchange in a signed,
// tamper-evident log.
package main

import (
	"fmt"
	"os"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `blackbox records what AI agents do in a tamper-evident log.

Usage:
  blackbox init     [--dir DIR]                     create the gateway's signing key
  blackbox serve    --upstream URL [flags]          run the gateway
  blackbox verify   [--log FILE] [--pub FILE]       check the log has not been altered
  blackbox sessions [--log FILE]                    list recorded agent sessions
  blackbox show     [--log FILE] SESSION            show what happened in a session
  blackbox version                                  print the version

Run "blackbox COMMAND -h" for the flags of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var code int
	switch cmd {
	case "init":
		code = runInit(args)
	case "serve":
		code = runServe(args)
	case "verify":
		code = runVerify(args)
	case "sessions":
		code = runSessions(args)
	case "show":
		code = runShow(args)
	case "version", "--version":
		fmt.Println("blackbox", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "blackbox: unknown command %q\n\n%s", cmd, usage)
		code = 2
	}
	os.Exit(code)
}

func fail(format string, args ...any) int { return failCode(1, format, args...) }

func failCode(code int, format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "blackbox: "+format+"\n", args...)
	return code
}
