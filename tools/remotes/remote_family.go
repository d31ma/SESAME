package remotes

type RemoteFamily struct {
	Words   Words
	Path    string
	Methods []RemoteMethod
}

func (family RemoteFamily) ClassName() string {
	return family.prefix() + family.Words.Pascal() + family.suffix()
}

func (family RemoteFamily) prefix() string {
	return "Sesame"
}

func (family RemoteFamily) suffix() string {
	return "Client"
}
