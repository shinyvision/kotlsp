package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/shinyvision/kotlsp/internal/lsp"
	"github.com/shinyvision/kotlsp/internal/resourcebudget"
)

var version = "dev"

func main() {
	// How far the heap may grow before the next collection. Each collection
	// marks the whole index, so a larger value trades memory for CPU.
	gcPercent := 100
	if value, err := strconv.Atoi(os.Getenv("KOTLSP_GOGC")); err == nil && value >= 25 && value <= 1000 {
		gcPercent = value
	}
	debug.SetGCPercent(gcPercent)
	// Same computation the reservation coordinator applies, so startup and
	// every later adjustment agree on one number.
	resourcebudget.ApplyGoMemoryLimit()
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-version":
			fmt.Printf("kotlsp %s\n", version)
			return
		case "benchmark":
			if err := lsp.RunBenchmarkCLI(context.Background(), os.Args[2:], os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
	}

	fs := flag.NewFlagSet("kotlsp", flag.ExitOnError)
	stdio := fs.Bool("stdio", true, "serve Language Server Protocol over stdin/stdout")
	logFile := fs.String("log-file", "", "write diagnostic logs to this file (never stdout)")
	_ = fs.Parse(os.Args[1:])
	if *logFile == "" {
		// Lets a session started by an editor be traced without changing its command line.
		*logFile = os.Getenv("KOTLSP_LOG_FILE")
	}
	if !*stdio {
		fmt.Fprintln(os.Stderr, "only --stdio is currently supported")
		os.Exit(2)
	}
	// KOTLSP_CPU_PROFILE=path profiles the first KOTLSP_CPU_PROFILE_SECONDS
	// (default 15) of the process, which covers a cold start. The server
	// exits through os.Exit, so a deferred stop would never run.
	if profilePath := os.Getenv("KOTLSP_CPU_PROFILE"); profilePath != "" {
		seconds := 15
		if value, err := strconv.Atoi(os.Getenv("KOTLSP_CPU_PROFILE_SECONDS")); err == nil && value > 0 {
			seconds = value
		}
		if profile, err := os.Create(profilePath); err == nil && pprof.StartCPUProfile(profile) == nil {
			time.AfterFunc(time.Duration(seconds)*time.Second, func() {
				pprof.StopCPUProfile()
				_ = profile.Close()
			})
		}
	}
	installProfileSignals()
	if profilePath := os.Getenv("KOTLSP_HEAP_PROFILE"); profilePath != "" {
		defer func() {
			if profile, err := os.Create(profilePath); err == nil {
				_ = pprof.WriteHeapProfile(profile)
				_ = profile.Close()
			}
		}()
	}
	if err := lsp.Serve(context.Background(), os.Stdin, os.Stdout, *logFile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
