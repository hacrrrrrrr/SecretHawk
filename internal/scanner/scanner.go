package scanner

import (
  "bufio"
  "fmt"
  "io/fs"
  "os"
  "path/filepath"
  "strings"
  "github.com/hacrrrrrrr/SecretHawk/internal/detector"
  "github.com/hacrrrrrrr/SecretHawk/internal/model"
)

func ScanPath(root string) ([]model.Finding,error) {
  info,err:=os.Stat(root); if err!=nil{return nil,err}; if !info.IsDir(){return scanFile(root)}
  var findings []model.Finding
  err=filepath.WalkDir(root,func(path string,d fs.DirEntry,walkErr error) error {
    if walkErr!=nil{return walkErr}; if d.IsDir(){if d.Name()==".git"||d.Name()=="node_modules"||d.Name()=="vendor"{return filepath.SkipDir};return nil}
    if shouldSkip(path){return nil}; f,e:=scanFile(path); if e==nil{findings=append(findings,f...)}; return nil
  }); return findings,err
}

func scanFile(path string)([]model.Finding,error) {
  file,err:=os.Open(path); if err!=nil{return nil,err}; defer file.Close()
  info,err:=file.Stat(); if err!=nil{return nil,err}; if info.Size()>10<<20{return nil,fmt.Errorf("file too large")}
  sc:=bufio.NewScanner(file); sc.Buffer(make([]byte,64*1024),2<<20); var findings []model.Finding; line:=0
  for sc.Scan(){line++; findings=append(findings,detector.ScanLine(path,line,sc.Text())...)}; return findings,sc.Err()
}

func shouldSkip(path string) bool {
  base:=filepath.Base(path); if strings.HasPrefix(base,".")&&base!=".env"{return true}; ext:=strings.ToLower(filepath.Ext(path))
  switch ext {case ".png",".jpg",".jpeg",".gif",".webp",".zip",".gz",".pdf",".exe",".dll",".so",".bin":return true}; return false
}