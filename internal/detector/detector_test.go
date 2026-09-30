package detector

import "testing"

func TestAWSAccessKey(t *testing.T) {
  got:=ScanLine("test.go",4,"key = \"AKIA1234567890ABCDEF\"")
  if len(got)!=1 {t.Fatalf("expected one finding, got %d",len(got))}
  if got[0].Detector!="aws-access-key" {t.Fatalf("unexpected detector: %s",got[0].Detector)}
  if got[0].Match=="AKIA1234567890ABCDEF" {t.Fatal("secret was not redacted")}
}