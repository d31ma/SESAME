package contract_test

import (
	"sort"
	"strings"
	"testing"
)

func TestEveryOperationHasOneHTTPCoverageCategory(t *testing.T) {
	t.Parallel()

	loaded, _ := loadManifest(t)
	declared := map[string]bool{}
	for _, operation := range loaded.Operations {
		declared[operation] = true
		coverage, found := loaded.HTTPCoverage[operation]
		if !found {
			t.Errorf("%s has no http_coverage entry; give it one of: %s", operation, coverageCategoriesDescription)
			continue
		}
		if !coverage.hasKnownCategory() {
			t.Errorf("%s has category %q; want one of: %s", operation, coverage.Category, coverageCategoriesDescription)
		}
		if !coverage.mayBeRouted() && (len(coverage.Routes) != 0 || coverage.Reason == "") {
			t.Errorf("%s is %s, so it must list no routes and must give a reason", operation, coverage.Category)
		}
		if coverage.mayBeRouted() && len(coverage.Routes) == 0 {
			t.Errorf("%s is %s but lists no route", operation, coverage.Category)
		}
	}
	for operation := range loaded.HTTPCoverage {
		if !declared[operation] {
			t.Errorf("http_coverage names %s, which is not in the manifest's operations", operation)
		}
	}
}

func TestHTTPCoverageMatchesTheYonRoutes(t *testing.T) {
	t.Parallel()

	loaded, root := loadManifest(t)
	table := loadRouteTable(t, root)
	for operation, coverage := range loaded.HTTPCoverage {
		for _, route := range coverage.Routes {
			named, exists := table[route]
			if !exists {
				t.Errorf("%s lists %s, which no Yon controller serves", operation, route)
				continue
			}
			wanted := operation
			if coverage.Category == coverageStandardEndpoint {
				wanted = coverage.Endpoint
			}
			if _, names := named[wanted]; wanted != "" && !names {
				t.Errorf("%s lists %s, but that route never names %q", operation, route, wanted)
			}
		}
		if coverage.Category == coverageRouted {
			continue
		}
		for route, named := range table {
			if _, names := named[operation]; names && !coverage.lists(route) {
				t.Errorf("%s is %s, but %s names it", operation, coverage.Category, route)
			}
		}
	}
}

func TestEveryYonRouteIsAccountedFor(t *testing.T) {
	t.Parallel()

	loaded, root := loadManifest(t)
	var unaccounted []string
	for route := range loadRouteTable(t, root) {
		accounted := false
		for _, coverage := range loaded.HTTPCoverage {
			accounted = accounted || coverage.lists(route)
		}
		if !accounted {
			unaccounted = append(unaccounted, route)
		}
	}
	sort.Strings(unaccounted)
	if len(unaccounted) != 0 {
		t.Errorf("Yon routes no http_coverage entry lists: %s", strings.Join(unaccounted, ", "))
	}
}
