package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"tailscale.com/util/winutil/gp"
	"tailscale.com/util/winutil/gp/regext"
)

func main() {
	polFile := flag.String("polfile", "", "path to policy file")
	flag.Parse()
	if *polFile == "" {
		gp.DumpAppliedRegistryGPOs(func(format string, args ...any) { fmt.Printf(format+"\n", args...) })
		return
	}

	f, err := os.Open(*polFile)
	if err != nil {
		log.Fatalf("Error opening %q: %v", *polFile, err)
	}

	pr, err := regext.NewReaderTakeOwnership(f)
	if err != nil {
		log.Fatalf("Error creating reader for %q: %v", *polFile, err)
	}
	defer pr.Close()

	for rc, err := range pr.Entries() {
		if err != nil {
			log.Fatalf("Error parsing entry: %v", err)
		}
		fmt.Printf("SubKey: %q\nValueName: %q\n", rc.SubKey, rc.ValueName)
	}
}
