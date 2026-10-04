package remotes

type RemoteMethod struct {
	Words           Words
	Verb            Words
	Path            string
	Operation       string
	Route           string
	Access          string
	Header          string
	HeaderParameter Words
	HasBody         bool
}
