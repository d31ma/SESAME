package remotes

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

type FamilyIndex struct{}

func (index FamilyIndex) Families(routes []Route) ([]RemoteFamily, error) {
	families := map[string]RemoteFamily{}
	failure := index.collect(families, routes)
	return index.sorted(families), errors.Join(failure, index.uniqueNames(families))
}

func (index FamilyIndex) collect(families map[string]RemoteFamily, routes []Route) error {
	failures := []error{}
	for _, route := range routes {
		failures = append(failures, index.add(families, route))
	}
	return errors.Join(failures...)
}

func (index FamilyIndex) add(families map[string]RemoteFamily, route Route) error {
	split := strings.LastIndex(route.Path, "/")
	familyPath, name := route.Path[:split], route.Path[split+1:]
	familyName, familyFailure := index.familyName(familyPath)
	familyWords := Words(strings.Split(familyName, "-"))
	method, methodFailure := index.method(route, familyWords, name)
	failure := errors.Join(familyFailure, methodFailure, index.checkedName(route, name))
	index.store(families, RemoteFamily{Words: familyWords, Path: familyPath}, method, failure)
	return failure
}

func (index FamilyIndex) store(families map[string]RemoteFamily, family RemoteFamily, method RemoteMethod, failure error) {
	if failure != nil {
		return
	}
	family.Methods = append(families[family.Path].Methods, method)
	families[family.Path] = family
}

func (index FamilyIndex) familyName(familyPath string) (string, error) {
	name, standard := index.standardFamilies()[familyPath]
	routed, isRouted := strings.CutPrefix(familyPath, index.routedPrefix())
	switch {
	case standard:
		return name, nil
	case isRouted && index.plainName(routed):
		return routed, nil
	}
	return "", fmt.Errorf("%s is neither %s<family>/<operation> nor a standard endpoint", familyPath, index.routedPrefix())
}

func (index FamilyIndex) checkedName(route Route, name string) error {
	if index.plainName(name) {
		return nil
	}
	return fmt.Errorf("%s ends in %q, which is not lowercase words joined by hyphens", route.Text(), name)
}

func (index FamilyIndex) plainName(name string) bool {
	return regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z][a-z0-9]*)*$`).MatchString(name)
}

func (index FamilyIndex) method(route Route, family Words, name string) (RemoteMethod, error) {
	headers := index.headersFor(family)
	header, known := headers[route.Access]
	method := RemoteMethod{
		Words:           Words(strings.Split(name, "-")),
		Verb:            Words{strings.ToLower(route.Method)},
		Path:            "/" + name,
		Operation:       route.Operation,
		Route:           route.Text(),
		Access:          route.Access,
		Header:          header,
		HeaderParameter: index.headerParameters()[header],
		HasBody:         route.Method == index.bodyMethod(),
	}
	return method, index.checkedRoute(route, known)
}

func (index FamilyIndex) checkedRoute(route Route, knownAccess bool) error {
	if knownAccess && slices.Contains(index.methods(), route.Method) {
		return nil
	}
	return fmt.Errorf("%s needs an access of %s and a method of %s", route.Text(), strings.Join(index.accessLevels(), ", "), strings.Join(index.methods(), ", "))
}

func (index FamilyIndex) headersFor(family Words) map[string]string {
	headers := map[string]string{
		index.publicAccess():        "",
		index.signedInAccess():      index.sessionHeader(),
		index.administratorAccess(): index.sessionHeader(),
	}
	if family.Kebab() == index.provisioningFamily() {
		headers[index.publicAccess()] = index.bearerHeader()
	}
	return headers
}

func (index FamilyIndex) uniqueNames(families map[string]RemoteFamily) error {
	failures := []error{}
	for _, family := range families {
		failures = append(failures, index.uniqueMethodNames(family))
	}
	return errors.Join(failures...)
}

func (index FamilyIndex) uniqueMethodNames(family RemoteFamily) error {
	seen := map[string]bool{}
	failures := []error{}
	for _, method := range family.Methods {
		failures = append(failures, index.firstUse(seen, family, method))
	}
	return errors.Join(failures...)
}

func (index FamilyIndex) firstUse(seen map[string]bool, family RemoteFamily, method RemoteMethod) error {
	name := method.Words.Kebab()
	if seen[name] {
		return fmt.Errorf("%s would have two methods named %q", family.ClassName(), name)
	}
	seen[name] = true
	return nil
}

func (index FamilyIndex) sorted(families map[string]RemoteFamily) []RemoteFamily {
	sortedFamilies := make([]RemoteFamily, 0, len(families))
	for _, family := range families {
		sortedFamilies = append(sortedFamilies, family)
	}
	sort.Slice(sortedFamilies, func(left int, right int) bool {
		return sortedFamilies[left].ClassName() < sortedFamilies[right].ClassName()
	})
	return sortedFamilies
}

func (index FamilyIndex) headerParameters() map[string]Words {
	return map[string]Words{
		index.sessionHeader(): {"session"},
		index.bearerHeader():  {"authorization"},
	}
}

func (index FamilyIndex) standardFamilies() map[string]string {
	return map[string]string{"/oidc": "standards"}
}

func (index FamilyIndex) routedPrefix() string {
	return "/api/v1/"
}

func (index FamilyIndex) provisioningFamily() string {
	return "scim"
}

func (index FamilyIndex) sessionHeader() string {
	return "Sesame-Session"
}

func (index FamilyIndex) bearerHeader() string {
	return "Authorization"
}

func (index FamilyIndex) bodyMethod() string {
	return "POST"
}

func (index FamilyIndex) methods() []string {
	return []string{"GET", index.bodyMethod()}
}

func (index FamilyIndex) publicAccess() string {
	return "public"
}

func (index FamilyIndex) signedInAccess() string {
	return "signed_in"
}

func (index FamilyIndex) administratorAccess() string {
	return "administrator"
}

func (index FamilyIndex) accessLevels() []string {
	return []string{index.publicAccess(), index.signedInAccess(), index.administratorAccess()}
}
