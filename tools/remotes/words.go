package remotes

import "strings"

type Words []string

func (words Words) Pascal() string {
	return words.joined(words.capitalized, "")
}

func (words Words) Camel() string {
	pascal := words.Pascal()
	return strings.ToLower(words.firstLetter(pascal)) + strings.TrimPrefix(pascal, words.firstLetter(pascal))
}

func (words Words) Snake() string {
	return words.joined(strings.ToLower, "_")
}

func (words Words) Kebab() string {
	return words.joined(strings.ToLower, "-")
}

func (words Words) joined(change func(string) string, separator string) string {
	changed := make([]string, 0, len(words))
	for _, word := range words {
		changed = append(changed, change(word))
	}
	return strings.Join(changed, separator)
}

func (words Words) capitalized(word string) string {
	first := words.firstLetter(word)
	return strings.ToUpper(first) + strings.ToLower(strings.TrimPrefix(word, first))
}

func (words Words) firstLetter(word string) string {
	if word == "" {
		return ""
	}
	return word[:1]
}
