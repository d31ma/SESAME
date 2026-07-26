// Command coverage gates statement coverage per package group.
//
// A single module-wide threshold would be either meaningless or immediately
// red: the CLI and tooling packages sit far below the domain, and averaging
// them produces a number that says nothing about whether the security-critical
// code is tested. So each group carries its own floor.
//
// The floors are set just below where each group stands today. That makes this
// a ratchet against regression rather than an aspiration — it fails when
// coverage drops, and raising a floor is a deliberate edit.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// group is one floor over a path prefix.
type group struct {
	name    string
	match   string
	floor   float64
	comment string
}

// Ordered most-specific first; a file is counted by the first group it
// matches, so overlapping prefixes are unambiguous.
var groups = []group{
	{"internal/domain", "/internal/domain/", 80.0,
		"protocol, crypto, and policy logic — the part with no excuse"},
	{"internal/application", "/internal/application/", 75.0,
		"commands, projections, and the security invariants across them"},
	{"internal/adapters", "/internal/adapters/", 68.0,
		"FYLO transport and the machine protocol edge"},
	{"internal/platform", "/internal/platform/", 30.0,
		"deployment and CLI wiring; the CLI is thin and largely drives the above"},
}

var funcLine = regexp.MustCompile(`^(\S+\.go):\d+:\s+\S+\s+([\d.]+)%$`)

func main() {
	profile := flag.String("profile", "", "coverage profile from go test -coverprofile")
	flag.Parse()
	if *profile == "" {
		fmt.Fprintln(os.Stderr, "usage: coverage -profile <file>")
		os.Exit(2)
	}

	report, err := exec.Command("go", "tool", "cover", "-func="+*profile).Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read the coverage profile: %v\n", err)
		os.Exit(1)
	}

	totals := map[string]*struct{ sum, count float64 }{}
	scanner := bufio.NewScanner(strings.NewReader(string(report)))
	for scanner.Scan() {
		match := funcLine.FindStringSubmatch(scanner.Text())
		if match == nil {
			continue
		}
		percent, err := strconv.ParseFloat(match[2], 64)
		if err != nil {
			continue
		}
		for _, g := range groups {
			if strings.Contains(match[1], g.match) {
				if totals[g.name] == nil {
					totals[g.name] = &struct{ sum, count float64 }{}
				}
				totals[g.name].sum += percent
				totals[g.name].count++
				break
			}
		}
	}

	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.name)
	}
	sort.Strings(names)

	failed := false
	for _, g := range groups {
		total := totals[g.name]
		if total == nil || total.count == 0 {
			// A group with no measured functions means the profile did not
			// cover it, which is a broken invocation rather than a pass.
			fmt.Printf("FAIL  %-22s no functions measured\n", g.name)
			failed = true
			continue
		}
		average := total.sum / total.count
		status := "ok  "
		if average < g.floor {
			status = "FAIL"
			failed = true
		}
		fmt.Printf("%s  %-22s %5.1f%%  (floor %.0f%%, %.0f functions) — %s\n",
			status, g.name, average, g.floor, total.count, g.comment)
	}

	if failed {
		fmt.Fprintln(os.Stderr, "\ncoverage fell below a floor; add tests or change the floor deliberately")
		os.Exit(1)
	}
}
