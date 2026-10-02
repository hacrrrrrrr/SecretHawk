package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/hacrrrrrrr/SecretHawk/internal/baseline"
	"github.com/hacrrrrrrr/SecretHawk/internal/cache"
	"github.com/hacrrrrrrr/SecretHawk/internal/config"
	"github.com/hacrrrrrrr/SecretHawk/internal/gitx"
	"github.com/hacrrrrrrr/SecretHawk/internal/model"
	"github.com/hacrrrrrrr/SecretHawk/internal/output"
	"github.com/hacrrrrrrr/SecretHawk/internal/scanner"
)

const version = "0.4.0"

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		base := filepath.Base(args[0])
		if base == "secrethawk" || base == "secrethawk.exe" { args = args[1:] }
	}
	if len(args) == 0 { printHelp(); return }

	switch args[0] {
	case "scan":
		runScan(args[1:])
	case "git":
		runGit(args[1:])
	case "version", "--version", "-v":
		fmt.Println("SecretHawk", version)
	case "help", "--help", "-h":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		printHelp()
		os.Exit(2)
	}
}

type scanFlags struct {
	format, configPath, baselinePath string
	fail, updateBaseline, noCache bool
	workers int
}

func parseCommon(fs *flag.FlagSet, f *scanFlags) {
	fs.StringVar(&f.format, "format", "text", "output format: text, json, or sarif")
	fs.StringVar(&f.configPath, "config", "", "JSON config file (default: .secrethawk.json)")
	fs.StringVar(&f.baselinePath, "baseline", "", "baseline file used to suppress known findings")
	fs.BoolVar(&f.fail, "fail-on-secret", false, "exit 1 when findings are detected")
	fs.BoolVar(&f.updateBaseline, "update-baseline", false, "write current findings to the baseline file")
	fs.BoolVar(&f.noCache, "no-cache", false, "disable incremental result cache")
	fs.IntVar(&f.workers, "workers", 0, "parallel scan workers (default: CPU count)")
}

func buildOptions(f scanFlags) (scanner.Options, *cache.Store, error) {
	cfg, err := config.Load(f.configPath)
	if err != nil { return scanner.Options{}, nil, err }
	opts := scanner.DefaultOptions()
	opts.Workers = cfg.Workers
	opts.MaxFileSize = cfg.MaxFileSize
	opts.ConfidenceThreshold = cfg.ConfidenceThreshold
	opts.IgnorePaths = cfg.IgnorePaths
	opts.IgnoreExtensions = cfg.IgnoreExtensions
	opts.DisabledDetectors = cfg.DisabledDetectors
	opts.DetectorPacks = cfg.DetectorPacks
	opts.EntropyThreshold = cfg.EntropyThreshold
	if f.workers > 0 { opts.Workers = f.workers }

	basePath := f.baselinePath
	if basePath == "" { basePath = cfg.BaselineFile }
	base, err := baseline.Load(basePath)
	if err != nil { return opts, nil, err }
	opts.Baseline = base

	if f.noCache { return opts, nil, nil }
	cachePath := cfg.CacheFile
	if cachePath != "" {
		store, err := cache.Load(cachePath)
		if err != nil { return opts, nil, err }
		opts.Cache = store
	}
	return opts, opts.Cache, nil
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var f scanFlags
	parseCommon(fs, &f)
	help := fs.Bool("help", false, "show scan help")
	if err := fs.Parse(args); err != nil { os.Exit(2) }
	if *help { printScanHelp(); return }

	target := "."
	if fs.NArg() > 0 { target = fs.Arg(0) }
	if fs.NArg() > 1 { fmt.Fprintln(os.Stderr, "error: scan accepts at most one path"); os.Exit(2) }

	opts, _, err := buildOptions(f)
	if err != nil { fmt.Fprintln(os.Stderr, "config error:", err); os.Exit(2) }
	findings, err := scanner.ScanPathWithOptions(target, opts)
	if err != nil { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
	finish(findings, f, opts)
}

func runGit(args []string) {
	fs := flag.NewFlagSet("git", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var f scanFlags
	parseCommon(fs, &f)
	history := fs.Bool("history", false, "scan Git commit history and diffs")
	help := fs.Bool("help", false, "show git help")
	if err := fs.Parse(args); err != nil { os.Exit(2) }
	if *help { printGitHelp(); return }
	if fs.NArg() != 1 { fmt.Fprintln(os.Stderr, "error: git requires exactly one repository path or URL"); printGitHelp(); os.Exit(2) }

	repo, cleanup, err := gitx.Prepare(fs.Arg(0))
	if err != nil { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
	defer cleanup()

	opts, _, err := buildOptions(f)
	if err != nil { fmt.Fprintln(os.Stderr, "config error:", err); os.Exit(2) }
	findings, err := scanner.ScanPathWithOptions(repo, opts)
	if err != nil { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }

	if *history {
		hf, err := scanner.ScanHistory(repo)
		if err != nil { fmt.Fprintln(os.Stderr, "history error:", err); os.Exit(1) }
		findings = scanner.Deduplicate(append(findings, hf...))
	}
	finish(findings, f, opts)
}

func finish(findings []model.Finding, f scanFlags, opts scanner.Options) {
	basePath := f.baselinePath
	if basePath == "" {
		if cfg, err := config.Load(f.configPath); err == nil { basePath = cfg.BaselineFile }
	}
	if f.updateBaseline {
		if basePath == "" { basePath = ".secrethawk-baseline.json" }
		if err := baseline.Save(basePath, findings); err != nil { fmt.Fprintln(os.Stderr, "baseline error:", err); os.Exit(1) }
		fmt.Fprintln(os.Stderr, "baseline updated:", basePath)
	}
	render(findings, f.format, f.fail)
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

func printHelp() {
	fmt.Println("SecretHawk - fast, extensible secret scanning")
	fmt.Println()
	fmt.Println("Usage: secrethawk <command> [options]")
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
	fmt.Println("  secrethawk scan . --baseline .secrethawk-baseline.json")
	fmt.Println("  secrethawk scan . --update-baseline --baseline .secrethawk-baseline.json")
	fmt.Println("  secrethawk git ./repo --history --format sarif")
	fmt.Println("  secrethawk version")
	fmt.Println()
	fmt.Println("Run 'secrethawk <command> --help' for command-specific help.")
}

func printScanHelp() {
	fmt.Println("Usage: secrethawk scan [path] [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --format <format>          text, json, or sarif")
	fmt.Println("  --config <file>            JSON configuration file")
	fmt.Println("  --baseline <file>          suppress known findings")
	fmt.Println("  --update-baseline          write findings to the baseline file")
	fmt.Println("  --no-cache                  disable incremental cache")
	fmt.Println("  --workers <n>               parallel workers")
	fmt.Println("  --fail-on-secret            exit 1 when findings exist")
	fmt.Println("  -h, --help                  show scan help")
}

func printGitHelp() {
	fmt.Println("Usage: secrethawk git <path-or-url> [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --history                   scan Git commit history and diffs")
	fmt.Println("  --format <format>           text, json, or sarif")
	fmt.Println("  --config <file>             JSON configuration file")
	fmt.Println("  --baseline <file>           suppress known findings")
	fmt.Println("  --update-baseline           write findings to the baseline file")
	fmt.Println("  --no-cache                  disable incremental cache")
	fmt.Println("  --workers <n>                parallel workers")
	fmt.Println("  --fail-on-secret             exit 1 when findings exist")
	fmt.Println("  -h, --help                   show git help")
}

var _ = runtime.NumCPU
