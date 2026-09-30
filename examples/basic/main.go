package main

import (
	"fmt"
	"log"

	"github.com/hacrrrrrrr/SecretHawk/pkg/secrethawk"
)

func main() {
	findings, err := secrethawk.Scan(".")
	if err != nil {
		log.Fatal(err)
	}

	for _, finding := range findings {
		fmt.Printf("%s %s %s:%d\n",
			finding.Severity,
			finding.Detector,
			finding.Path,
			finding.Line,
		)
	}
}
