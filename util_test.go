package snmpgo_test

import (
	"testing"

	"github.com/k-sone/snmpgo"
)

func TestHoge(t *testing.T) {
	expStr := "1234567890abcdef"

	str := expStr
	if expStr != snmpgo.StripHexPrefix(str) {
		t.Errorf("stripHexPrefix() - expected [%s], actual[%s]", expStr, str)
	}

	str = "0x" + expStr
	if expStr != snmpgo.StripHexPrefix(str) {
		t.Errorf("stripHexPrefix() - expected [%s], actual[%s]", expStr, str)
	}

	str = "0X" + expStr
	if expStr != snmpgo.StripHexPrefix(str) {
		t.Errorf("stripHexPrefix() - expected [%s], actual[%s]", expStr, str)
	}
}
