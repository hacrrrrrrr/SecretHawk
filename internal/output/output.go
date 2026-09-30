package output

import (
  "encoding/json"
  "fmt"
  "io"
  "github.com/hacrrrrrrr/SecretHawk/internal/model"
)

func Render(w io.Writer, findings []model.Finding, format string) error {
  switch format {
  case "json": enc:=json.NewEncoder(w); enc.SetIndent("","  "); return enc.Encode(findings)
  case "text": for _,f:=range findings { fmt.Fprintf(w,"[%s] %s (%d%%) %s:%d %s\\n",f.Severity,f.Detector,f.Confidence,f.Path,f.Line,f.Match) }; if len(findings)==0 {fmt.Fprintln(w,"No potential secrets found.")}; return nil
  default: return fmt.Errorf("unsupported format %q",format)
  }
}