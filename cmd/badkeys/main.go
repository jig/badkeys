// Command badkeys checks cryptographic public keys for known weaknesses.
//
// Usage:
//
//	badkeys [-checks a,b,c] [-recover] [-update-bl] [file ...]
//
// With no file arguments (and without -update-bl) it reads a key from stdin.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jig/badkeys"
)

func main() {
	checksFlag := flag.String("checks", "", "comma-separated checks to run (default: all default checks)")
	recover := flag.Bool("recover", false, "recover and print private keys when possible")
	updateBL := flag.Bool("update-bl", false, "download/update the blocklist, then exit")
	lookup := flag.Bool("lookup", false, "with -update-bl, also download the URL lookup file")
	flag.Parse()

	if *updateBL {
		err := badkeys.UpdateBlocklist(badkeys.UpdateOptions{
			Lookup: *lookup,
			Log:    func(s string) { fmt.Fprintln(os.Stderr, s) },
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "update failed:", err)
			os.Exit(1)
		}
		return
	}

	// Load the blocklist if present; ignore errors (it is optional).
	_ = badkeys.LoadDefaultBlocklist("")

	var opts []badkeys.Option
	if *checksFlag != "" {
		opts = append(opts, badkeys.WithChecks(strings.Split(*checksFlag, ",")...))
	}
	if *recover {
		opts = append(opts, badkeys.WithKeyRecover())
	}

	inputs := flag.Args()
	rc := 0
	if len(inputs) == 0 {
		data, _ := io.ReadAll(os.Stdin)
		if report("-", data, opts) {
			rc = 1
		}
	}
	for _, fn := range inputs {
		data, err := os.ReadFile(fn)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			rc = 1
			continue
		}
		if report(fn, data, opts) {
			rc = 1
		}
	}
	os.Exit(rc)
}

func report(name string, data []byte, opts []badkeys.Option) bool {
	r := badkeys.DetectAndCheck(data, opts...)
	switch r.Warn {
	case "":
	case badkeys.WarnFallbackParser:
		fmt.Fprintf(os.Stderr, "WARNING: X.509 error, using fallback parser, %s\n", name)
	default:
		fmt.Fprintf(os.Stderr, "WARNING: %s, %s\n", r.Warn, name)
	}
	if !r.Flagged() {
		fmt.Printf("%s: %s, no problems found\n", name, r.Type)
		return false
	}
	fmt.Printf("%s: %s, PROBLEMS FOUND:\n", name, r.Type)
	for _, c := range badkeys.AllChecks() {
		f, ok := r.Findings[c]
		if !ok {
			continue
		}
		line := "  " + f.Check
		if f.Subtest != "" {
			line += " (" + f.Subtest + ")"
		}
		fmt.Println(line)
		if f.PrivateKey != "" {
			fmt.Println(f.PrivateKey)
		}
	}
	return true
}
