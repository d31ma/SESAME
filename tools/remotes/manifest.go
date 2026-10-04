package remotes

type Manifest struct {
	HTTPCoverage map[string]Coverage `json:"http_coverage"`
}
