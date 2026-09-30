package main

import (
  "flag"
  "fmt"
  "os"

  "github.com/hacrrrrrrr/SecretHawk/internal/output"
  "github.com/hacrrrrrrr/SecretHawk/internal/scanner"
)

func main() {
  if len(os.Args) < 2 { usage(); os.Exit(2) }
  switch os.Args[1] {
  case "scan":
    fs := flag.NewFlagSet("scan", flag.ExitOnError)
    format := fs.String("format", "text", "output format: text or json")
    fail := fs.Bool("fail-on-secret", false, "exit 1 when findings are detected")
    _ = fs.Parse(os.Args[2:])
    target := "."; if fs.NArg() > 0 { target = fs.Arg(0) }
    findings, err := scanner.ScanPath(target)
    if err != nil { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
    if err := output.Render(os.Stdout, findings, *format); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
    if *fail && len(findings) > 0 { os.Exit(1) }
  default: usage(); os.Exit(2)
  }
}

func usage() { fmt.Println("SecretHawk - source secret scanner"); fmt.Println("Usage: secrethawk scan [path] [--format text|json] [--fail-on-secret]") }