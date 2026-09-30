package main

import (
  "os"
  "testing"

  "github.com/hacrrrrrrr/SecretHawk/internal/scanner"
)

func TestScanCurrentTree(t *testing.T) {
  findings,err:=scanner.ScanPath(".")
  if err!=nil {t.Fatal(err)}
  _=findings
  _=os.Stdout
}