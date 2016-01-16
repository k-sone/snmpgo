package snmpgo_test

import (
	"fmt"
	"testing"

	"github.com/k-sone/snmpgo"
)

func TestStripHexPrefix(t *testing.T) {
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

func TestRetry(t *testing.T) {
	count := 0
	f := func() error {
		count += 1
		return nil
	}
	if err := snmpgo.Retry(5, f); err != nil || count != 1 {
		t.Errorf("retry() - normal: err=%s, count=%d", err, count)
	}

	count = 0
	f = func() error {
		count += 1
		return fmt.Errorf("error")
	}
	if err := snmpgo.Retry(5, f); err == nil || count != 1 {
		t.Errorf("retry() - not retry: err=%s, count=%d", err, count)
	}

	count = 0
	f = func() error {
		count += 1
		return snmpgo.NewNotInTimeWindowError()
	}
	if err := snmpgo.Retry(5, f); err == nil || count != 6 {
		t.Errorf("retry() - error: err=%s, count=%d", err, count)
	}
}
