package remotes

type Route struct {
	Operation string
	Method    string
	Path      string
	Access    string
}

func (route Route) Text() string {
	return route.Method + " " + route.Path
}
