package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hacrrrrrrr/SecretHawk/internal/gitx"
	"github.com/hacrrrrrrr/SecretHawk/internal/model"
	"github.com/hacrrrrrrr/SecretHawk/internal/output"
	"github.com/hacrrrrrrr/SecretHawk/internal/scanner"
)

func main() {
	if len(os.Args) < 2 { usage(); os.Exit(2) }
	switch os.Args[1] {
	case "scan": runScan(os.Args[2:])
	case "git": runGit(os.Args[2:])
	default: usage(); os.Exit(2)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	format := fs.String("format", "text", "output format: text, json, or sarif")
	fail := fs.Bool("fail-on-secret", false, "exit 1 when findings are detected")
	_ = fs.Parse(args)
	target := "."
	if fs.NArg() > 0 { target = fs.Arg(0) }
	findings, err := scanner.ScanPath(target)
	if err != nil { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
	render(findings, *format, *fail)
}

func runGit(args []string) {
	fs := flag.NewFlagSet("git", flag.ExitOnError)
	format := fs.String("format", "text", "output format: text, json, or sarif")
	history := fs.Bool("history", false, "scan Git commit history")
	fail := fs.Bool("fail-on-secret", false, "exit 1 when findings are detected")
	_ = fs.Parse(args)
	if fs.NArg() < 1 { fmt.Fprintln(os.Stderr, "usage: secrethawk git <URL-or-path> [--history]"); os.Exit(2) }

	repo, cleanup, err := gitx.Prepare(fs.Arg(0))
	if err != nil { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
	defer cleanup()

	findings, err := scanner.ScanPath(repo)
	if err != nil { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
	if *history {
		hf, err := scanner.ScanHistory(repo)
		if err != nil { fmt.Fprintln(os.Stderr, "history error:", err); os.Exit(1) }
		findings = scanner.Deduplicate(append(findings, hf...))
	}
	render(findings, *format, *fail)
}

func render(findings []model.Finding, format string, fail bool) {
	var err error
	switch format {
	case "text", "json":
		err = output.Render(os.Stdout, findings, format)
	case "sarif":
		err = output.RenderSARIF(os.Stdout, findings)
	default:
		fmt.Fprintln(os.Stderr, "unsupported format:", format); os.Exit(2)
	}
	if err != nil { fmt.Fprintln(os.Stderr, "output error:", err); os.Exit(1) }
	if fail && len(findings) > 0 { os.Exit(1) }
}

func usage() {
	fmt.Println("SecretHawk - source secret scanner")
	fmt.Println("Usage:")
	fmt.Println("  secrethawk scan [path] [--format text|json|sarif]")
	fmt.Println("  secrethawk git <URL-or-path> [--history] [--format text|json|sarif]")
}
