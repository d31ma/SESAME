package authenticator

// A deliberately tiny CBOR reader.
//
// WebAuthn needs CBOR in exactly two places: the attestation object wrapper
// and the COSE public key inside it. Both are small, fixed-shape structures
// produced by an authenticator, and both arrive from an untrusted browser.
//
// A general CBOR library would be a large dependency and a large parsing
// surface for two structures this shape. What is here decodes only the major
// types those structures use, bounds every length against the remaining
// input, and refuses indefinite-length items, tags, floats, and anything
// else — so a malicious encoder has almost nothing to reach for.

import (
	"errors"
	"fmt"
	"math"
)

// cborValue is one decoded item. Exactly one field is meaningful, selected by
// kind.
type cborValue struct {
	kind     cborKind
	unsigned uint64
	negative int64
	bytes    []byte
	text     string
	array    []cborValue
	// pairs preserves map entries in encounter order. WebAuthn maps are tiny
	// and keyed by either small integers or short strings, so a slice beats a
	// map and keeps duplicate detection trivial.
	pairs  []cborPair
	simple bool
}

type cborKind int

const (
	cborUnsigned cborKind = iota
	cborNegative
	cborBytes
	cborText
	cborArray
	cborMap
	cborBool
	cborNull
)

type cborPair struct {
	key   cborValue
	value cborValue
}

const (
	// maxCBORDepth bounds nesting. WebAuthn structures nest three deep at
	// most; anything deeper is an encoder trying something.
	maxCBORDepth = 8
	// maxCBORItems bounds one map or array.
	maxCBORItems = 64
)

var errCBOR = errors.New("malformed CBOR")

// decodeCBOR decodes exactly one item and reports the unconsumed remainder.
func decodeCBOR(input []byte) (cborValue, []byte, error) {
	return decodeCBORAt(input, 0)
}

func decodeCBORAt(input []byte, depth int) (cborValue, []byte, error) {
	if depth > maxCBORDepth {
		return cborValue{}, nil, fmt.Errorf("%w: nesting exceeds %d", errCBOR, maxCBORDepth)
	}
	if len(input) == 0 {
		return cborValue{}, nil, fmt.Errorf("%w: truncated", errCBOR)
	}

	major := input[0] >> 5
	minor := input[0] & 0x1f
	rest := input[1:]

	// Indefinite-length items and the reserved additional-information values
	// are refused outright rather than interpreted.
	if minor >= 28 {
		return cborValue{}, nil, fmt.Errorf("%w: unsupported additional information %d", errCBOR, minor)
	}

	var argument uint64
	switch {
	case minor < 24:
		argument = uint64(minor)
	case minor == 24:
		if len(rest) < 1 {
			return cborValue{}, nil, fmt.Errorf("%w: truncated argument", errCBOR)
		}
		argument, rest = uint64(rest[0]), rest[1:]
	case minor == 25:
		if len(rest) < 2 {
			return cborValue{}, nil, fmt.Errorf("%w: truncated argument", errCBOR)
		}
		argument = uint64(rest[0])<<8 | uint64(rest[1])
		rest = rest[2:]
	case minor == 26:
		if len(rest) < 4 {
			return cborValue{}, nil, fmt.Errorf("%w: truncated argument", errCBOR)
		}
		argument = uint64(rest[0])<<24 | uint64(rest[1])<<16 | uint64(rest[2])<<8 | uint64(rest[3])
		rest = rest[4:]
	case minor == 27:
		if len(rest) < 8 {
			return cborValue{}, nil, fmt.Errorf("%w: truncated argument", errCBOR)
		}
		for index := 0; index < 8; index++ {
			argument = argument<<8 | uint64(rest[index])
		}
		rest = rest[8:]
	}

	switch major {
	case 0:
		return cborValue{kind: cborUnsigned, unsigned: argument}, rest, nil
	case 1:
		if argument > math.MaxInt64 {
			return cborValue{}, nil, fmt.Errorf("%w: negative integer out of range", errCBOR)
		}
		return cborValue{kind: cborNegative, negative: -1 - int64(argument)}, rest, nil
	case 2, 3:
		// A length is checked against what is actually left, so a claimed
		// four-gigabyte string cannot cause an allocation.
		if argument > uint64(len(rest)) {
			return cborValue{}, nil, fmt.Errorf("%w: length %d exceeds %d remaining bytes", errCBOR, argument, len(rest))
		}
		payload := rest[:argument]
		rest = rest[argument:]
		if major == 2 {
			return cborValue{kind: cborBytes, bytes: payload}, rest, nil
		}
		return cborValue{kind: cborText, text: string(payload)}, rest, nil
	case 4, 5:
		if argument > maxCBORItems {
			return cborValue{}, nil, fmt.Errorf("%w: %d items exceeds %d", errCBOR, argument, maxCBORItems)
		}
		if major == 4 {
			items := make([]cborValue, 0, argument)
			for index := uint64(0); index < argument; index++ {
				var item cborValue
				var err error
				item, rest, err = decodeCBORAt(rest, depth+1)
				if err != nil {
					return cborValue{}, nil, err
				}
				items = append(items, item)
			}
			return cborValue{kind: cborArray, array: items}, rest, nil
		}
		pairs := make([]cborPair, 0, argument)
		for index := uint64(0); index < argument; index++ {
			var key, value cborValue
			var err error
			key, rest, err = decodeCBORAt(rest, depth+1)
			if err != nil {
				return cborValue{}, nil, err
			}
			value, rest, err = decodeCBORAt(rest, depth+1)
			if err != nil {
				return cborValue{}, nil, err
			}
			// A duplicate key would let an encoder show one parser one value
			// and another parser a different one.
			for _, existing := range pairs {
				if sameCBORKey(existing.key, key) {
					return cborValue{}, nil, fmt.Errorf("%w: duplicate map key", errCBOR)
				}
			}
			pairs = append(pairs, cborPair{key: key, value: value})
		}
		return cborValue{kind: cborMap, pairs: pairs}, rest, nil
	case 7:
		switch argument {
		case 20:
			return cborValue{kind: cborBool, simple: false}, rest, nil
		case 21:
			return cborValue{kind: cborBool, simple: true}, rest, nil
		case 22:
			return cborValue{kind: cborNull}, rest, nil
		}
		return cborValue{}, nil, fmt.Errorf("%w: unsupported simple value %d", errCBOR, argument)
	}
	return cborValue{}, nil, fmt.Errorf("%w: unsupported major type %d", errCBOR, major)
}

func sameCBORKey(left, right cborValue) bool {
	if left.kind != right.kind {
		return false
	}
	switch left.kind {
	case cborUnsigned:
		return left.unsigned == right.unsigned
	case cborNegative:
		return left.negative == right.negative
	case cborText:
		return left.text == right.text
	default:
		return false
	}
}

// lookupText finds a text-keyed map entry.
func (v cborValue) lookupText(key string) (cborValue, bool) {
	if v.kind != cborMap {
		return cborValue{}, false
	}
	for _, pair := range v.pairs {
		if pair.key.kind == cborText && pair.key.text == key {
			return pair.value, true
		}
	}
	return cborValue{}, false
}

// lookupLabel finds an integer-keyed map entry, as COSE keys use. Negative
// labels are the curve parameters.
func (v cborValue) lookupLabel(label int64) (cborValue, bool) {
	if v.kind != cborMap {
		return cborValue{}, false
	}
	for _, pair := range v.pairs {
		switch {
		case pair.key.kind == cborUnsigned && label >= 0 && pair.key.unsigned == uint64(label):
			return pair.value, true
		case pair.key.kind == cborNegative && pair.key.negative == label:
			return pair.value, true
		}
	}
	return cborValue{}, false
}

// integer returns a signed value for either integer kind.
func (v cborValue) integer() (int64, bool) {
	switch v.kind {
	case cborUnsigned:
		if v.unsigned > math.MaxInt64 {
			return 0, false
		}
		return int64(v.unsigned), true
	case cborNegative:
		return v.negative, true
	default:
		return 0, false
	}
}
