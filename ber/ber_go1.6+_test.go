// +build go1.6

package ber

import (
	"encoding/asn1"
	"testing"
)

func TestMarshalNilValue(t *testing.T) {
	nilValueTestData := []interface{}{
		nil,
		struct{ V interface{} }{},
	}
	for i, test := range nilValueTestData {
		if _, err := Marshal(test); err == nil {
			t.Fatalf("#%d: successfully marshaled nil value", i)
		}
	}
}

type unexported struct {
	X int
	y int
}

type exported struct {
	X int
	Y int
}

func TestUnexportedStructField(t *testing.T) {
	want := asn1.StructuralError{Msg: "struct contains unexported fields"}

	_, err := Marshal(unexported{X: 5, y: 1})
	if err != want {
		t.Errorf("got %v, want %v", err, want)
	}

	bs, err := Marshal(exported{X: 5, Y: 1})
	if err != nil {
		t.Fatal(err)
	}
	var u unexported
	_, err = Unmarshal(bs, &u)
	if err != want {
		t.Errorf("got %v, want %v", err, want)
	}
}
