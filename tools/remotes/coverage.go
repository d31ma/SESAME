package remotes

type Coverage struct {
	Category string            `json:"category"`
	Routes   []string          `json:"routes"`
	Access   map[string]string `json:"access"`
}
