package scanner

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/hacrrrrrrr/SecretHawk/internal/baseline"
	"github.com/hacrrrrrrr/SecretHawk/internal/cache"
	"github.com/hacrrrrrrr/SecretHawk/internal/detector"
	"github.com/hacrrrrrrr/SecretHawk/internal/gitignore"
	"github.com/hacrrrrrrr/SecretHawk/internal/model"
)

type Options struct {
	MaxFileSize         int64
	Workers             int
	ConfidenceThreshold int
	IgnorePaths         []string
	IgnoreExtensions    []string
	DisabledDetectors   []string
	DetectorPacks       []string
	EntropyThreshold    float64
	Cache               *cache.Store
	Baseline            map[string]struct{}
}

func DefaultOptions() Options {
	return Options{MaxFileSize: 10 << 20, Workers: runtime.NumCPU(), EntropyThreshold: 4.2}
}

func ScanPath(root string) ([]model.Finding, error) {
	return ScanPathWithOptions(root, DefaultOptions())
}

func ScanPathWithOptions(root string, opts Options) ([]model.Finding, error) {
	if opts.MaxFileSize <= 0 { opts.MaxFileSize = 10 << 20 }
	if opts.Workers <= 0 { opts.Workers = runtime.NumCPU() }
	if opts.Workers > 64 { opts.Workers = 64 }
	if opts.EntropyThreshold <= 0 { opts.EntropyThreshold = 4.2 }

	active := detector.DefaultRules()
	packRules, err := detector.LoadPacks(opts.DetectorPacks)
	if err != nil { return nil, err }
	active = append(active, packRules...)
	active = detector.FilterRules(active, opts.DisabledDetectors)

	info, err := os.Stat(root)
	if err != nil { return nil, err }
	if !info.IsDir() {
		if shouldSkipWithOptions(root, opts) { return nil, nil }
		f, err := scanFile(root, opts, active)
		if err != nil { return nil, err }
		return filterFindings(Deduplicate(f), opts), nil
	}

	matcher := gitignore.New(root)
	paths := make([]string, 0, 1024)
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil { return walkErr }
		if path != root && matcher.Ignored(path, d.IsDir()) {
			if d.IsDir() { return filepath.SkipDir }
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "bin", "dist", "build":
				if path != root { return filepath.SkipDir }
			}
			return nil
		}
		if shouldSkipWithOptions(path, opts) { return nil }
		paths = append(paths, path)
		return nil
	})
	if err != nil { return nil, err }

	jobs := make(chan string)
	results := make(chan []model.Finding, opts.Workers)
	errs := make(chan error, 1)
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for path := range jobs {
			findings, err := scanFile(path, opts, active)
			if err != nil {
				select { case errs <- err: default: }
				continue
			}
			results <- findings
		}
	}
	for i := 0; i < opts.Workers; i++ { wg.Add(1); go worker() }
	go func() {
		for _, path := range paths { jobs <- path }
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var findings []model.Finding
	for batch := range results { findings = append(findings, batch...) }
	select { case err := <-errs: return nil, err; default: }
	if opts.Cache != nil {
		if err := opts.Cache.Save(); err != nil { return nil, err }
	}
	return filterFindings(Deduplicate(findings), opts), nil
}

func scanFile(path string, opts Options, active []detector.Rule) ([]model.Finding, error) {
	info, err := os.Stat(path)
	if err != nil { return nil, err }
	if info.Size() > opts.MaxFileSize {
		return nil, fmt.Errorf("file %s exceeds maximum scan size of %d bytes", path, opts.MaxFileSize)
	}
	if opts.Cache != nil {
		if cached, ok := opts.Cache.Get(path, info.Size(), info.ModTime().UnixNano(), optionsKey(opts)); ok {
			return cached, nil
		}
	}

	file, err := os.Open(path)
	if err != nil { return nil, err }
	defer file.Close()

	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	var findings []model.Finding
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		findings = append(findings, detector.ScanLineWithRules(path, line, text, active)...)
		findings = append(findings, entropyFinding(path, line, text, opts.EntropyThreshold)...)
	}
	if err := sc.Err(); err != nil { return nil, err }
	if opts.Cache != nil { opts.Cache.Put(path, info.Size(), info.ModTime().UnixNano(), optionsKey(opts), findings) }
	return findings, nil
}

func filterFindings(findings []model.Finding, opts Options) []model.Finding {
	out := findings[:0]
	for _, f := range findings {
		if opts.ConfidenceThreshold > 0 && f.Confidence < opts.ConfidenceThreshold { continue }
		if _, ok := opts.Baseline[baseline.Fingerprint(f)]; ok { continue }
		out = append(out, f)
	}
	return out
}

func shouldSkip(path string) bool { return shouldSkipWithOptions(path, DefaultOptions()) }

func shouldSkipWithOptions(path string, opts Options) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") && base != ".env" { return true }
	for _, ignored := range opts.IgnorePaths {
		if ok, _ := filepath.Match(ignored, path); ok || okBase(ignored, path) { return true }
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".zip", ".gz", ".pdf", ".exe", ".dll", ".so", ".bin":
		return true
	}
	for _, ignored := range opts.IgnoreExtensions {
		if strings.EqualFold(ignored, ext) || strings.EqualFold("."+strings.TrimPrefix(ignored, "."), ext) { return true }
	}
	return false
}

func okBase(pattern, path string) bool { return filepath.Base(path) == pattern }


func optionsKey(opts Options) string {
	type key struct {
		MaxFileSize int64
		Workers int
		ConfidenceThreshold int
		IgnorePaths []string
		IgnoreExtensions []string
		DisabledDetectors []string
		DetectorPacks []string
		EntropyThreshold float64
	}
	data, _ := json.Marshal(key{
		MaxFileSize:opts.MaxFileSize, Workers:opts.Workers,
		ConfidenceThreshold:opts.ConfidenceThreshold, IgnorePaths:opts.IgnorePaths,
		IgnoreExtensions:opts.IgnoreExtensions, DisabledDetectors:opts.DisabledDetectors,
		DetectorPacks:opts.DetectorPacks, EntropyThreshold:opts.EntropyThreshold,
	})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
