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

const version = "0.2.0"

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "git":
		runGit(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("SecretHawk", version)
	case "help", "--help", "-h":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		printHelp()
		os.Exit(2)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "text", "output format: text, json, or sarif")
	fail := fs.Bool("fail-on-secret", false, "exit 1 when findings are detected")
	help := fs.Bool("help", false, "show scan help")
	if err := fs.Parse(args); err != nil { os.Exit(2) }
	if *help {
		printScanHelp()
		return
	}

	target := "."
	if fs.NArg() > 0 { target = fs.Arg(0) }
	if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "error: scan accepts at most one path")
		os.Exit(2)
	}

	findings, err := scanner.ScanPath(target)
	if err != nil { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
	render(findings, *format, *fail)
}

func runGit(args []string) {
	fs := flag.NewFlagSet("git", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "text", "output format: text, json, or sarif")
	history := fs.Bool("history", false, "scan Git commit history")
	fail := fs.Bool("fail-on-secret", false, "exit 1 when findings are detected")
	help := fs.Bool("help", false, "show git help")
	if err := fs.Parse(args); err != nil { os.Exit(2) }
	if *help {
		printGitHelp()
		return
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "error: git requires exactly one repository path or URL")
		printGitHelp()
		os.Exit(2)
	}

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
		fmt.Fprintln(os.Stderr, "unsupported format:", format)
		os.Exit(2)
	}
	if err != nil { fmt.Fprintln(os.Stderr, "output error:", err); os.Exit(1) }
	if fail && len(findings) > 0 { os.Exit(1) }
}

func printHelp() {
	fmt.Println("SecretHawk - fast, extensible secret scanning")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  secrethawk <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  scan       Scan a local file or directory")
	fmt.Println("  git        Scan a local or remote Git repository")
	fmt.Println("  version    Print the SecretHawk version")
	fmt.Println("  help       Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  secrethawk scan .")
	fmt.Println("  secrethawk scan ./src --format json")
	fmt.Println("  secrethawk git ./repo")
	fmt.Println("  secrethawk git https://github.com/owner/repo.git")
	fmt.Println("  secrethawk git ./repo --history --format sarif")
	fmt.Println("  secrethawk version")
	fmt.Println()
	fmt.Println("Run 'secrethawk <command> --help' for command-specific help.")
}

func printScanHelp() {
	fmt.Println("Usage:")
	fmt.Println("  secrethawk scan [path] [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --format <format>       text, json, or sarif")
	fmt.Println("  --fail-on-secret        exit 1 when findings exist")
	fmt.Println("  -h, --help              show this help")
}

func printGitHelp() {
	fmt.Println("Usage:")
	fmt.Println("  secrethawk git <path-or-url> [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --history               scan Git commit history and diffs")
	fmt.Println("  --format <format>       text, json, or sarif")
	fmt.Println("  --fail-on-secret        exit 1 when findings exist")
	fmt.Println("  -h, --help              show this help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  secrethawk git ./repo")
	fmt.Println("  secrethawk git https://github.com/owner/repo.git")
	fmt.Println("  secrethawk git ./repo --history")
	fmt.Println("  secrethawk git ./repo --history --format sarif")
}
