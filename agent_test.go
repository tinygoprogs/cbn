package cbn

import (
	"net/url"
	"testing"
)

func TestEncodeVals(t *testing.T) {
	cases := map[string]url.Values{
		"a=b": url.Values{"a": {"b"}},
		//"a=b&c=d": url.Values{"a": {"b"}, "c": {"d"}}, // XXX may also be c=d&a=b
		"a=b,c": url.Values{"a": {"b", "c"}},
	}
	for expected, vals := range cases {
		enc := EncodeVals(vals)
		if enc != expected {
			t.Errorf("expected='%v', got='%v'", expected, enc)
		}
	}
}
