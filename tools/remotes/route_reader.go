package remotes

import (
	"slices"
	"sort"
	"strings"
)

type RouteReader struct {
	manifest Manifest
}

func (reader RouteReader) Routes() []Route {
	found := map[string]Route{}
	reader.addOperations(found, reader.operations())
	return reader.sorted(found)
}

func (reader RouteReader) addOperations(found map[string]Route, operations []string) {
	for _, operation := range operations {
		reader.addOperation(found, operation)
	}
}

func (reader RouteReader) operations() []string {
	operations := make([]string, 0, len(reader.manifest.HTTPCoverage))
	for operation := range reader.manifest.HTTPCoverage {
		operations = append(operations, operation)
	}
	sort.Strings(operations)
	return operations
}

func (reader RouteReader) addOperation(found map[string]Route, operation string) {
	coverage := reader.manifest.HTTPCoverage[operation]
	for _, text := range reader.wanted(coverage) {
		reader.addFirst(found, reader.route(operation, text, coverage))
	}
}

func (reader RouteReader) wanted(coverage Coverage) []string {
	switch coverage.Category {
	case reader.routedCategory():
		return coverage.Routes
	case reader.standardCategory():
		return reader.consumableStandardRoutes(coverage.Routes)
	}
	return nil
}

func (reader RouteReader) consumableStandardRoutes(routes []string) []string {
	consumable := []string{}
	for _, route := range routes {
		consumable = reader.appendConsumable(consumable, route)
	}
	return consumable
}

func (reader RouteReader) appendConsumable(consumable []string, route string) []string {
	if slices.Contains(reader.standardRoutes(), route) {
		return append(consumable, route)
	}
	return consumable
}

func (reader RouteReader) route(operation string, text string, coverage Coverage) Route {
	method, path, _ := strings.Cut(text, " ")
	return Route{Operation: operation, Method: method, Path: path, Access: coverage.Access[text]}
}

func (reader RouteReader) addFirst(found map[string]Route, route Route) {
	if _, known := found[route.Text()]; !known {
		found[route.Text()] = route
	}
}

func (reader RouteReader) sorted(found map[string]Route) []Route {
	routes := make([]Route, 0, len(found))
	for _, route := range found {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(left int, right int) bool { return routes[left].Text() < routes[right].Text() })
	return routes
}

func (reader RouteReader) routedCategory() string {
	return "routed"
}

func (reader RouteReader) standardCategory() string {
	return "standard_endpoint"
}

func (reader RouteReader) standardRoutes() []string {
	return []string{"GET /oidc/openid-configuration", "GET /oidc/jwks"}
}
