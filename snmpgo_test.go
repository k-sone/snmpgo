package snmpgo_test

import (
	"math"
	"testing"

	"github.com/k-sone/snmpgo"
)

func TestSNMPArguments(t *testing.T) {
	args := &snmpgo.SNMPArguments{Version: 2}
	err := snmpgo.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - version check")
	}

	args = &snmpgo.SNMPArguments{MessageMaxSize: -1}
	err = snmpgo.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - message size(min)")
	}

	args = &snmpgo.SNMPArguments{MessageMaxSize: math.MaxInt32 + 1}
	err = snmpgo.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - message size(max)")
	}

	args = &snmpgo.SNMPArguments{Version: snmpgo.V3}
	err = snmpgo.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - user name")
	}

	args = &snmpgo.SNMPArguments{
		Version:       snmpgo.V3,
		UserName:      "MyName",
		SecurityLevel: snmpgo.AuthNoPriv,
	}
	err = snmpgo.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - auth password")
	}

	args = &snmpgo.SNMPArguments{
		Version:       snmpgo.V3,
		UserName:      "MyName",
		SecurityLevel: snmpgo.AuthNoPriv,
		AuthPassword:  "aaaaaaaa",
	}
	err = snmpgo.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - auth protocol")
	}

	args = &snmpgo.SNMPArguments{
		Version:       snmpgo.V3,
		UserName:      "MyName",
		SecurityLevel: snmpgo.AuthPriv,
		AuthPassword:  "aaaaaaaa",
		AuthProtocol:  snmpgo.Md5,
	}
	err = snmpgo.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - priv password")
	}

	args = &snmpgo.SNMPArguments{
		Version:       snmpgo.V3,
		UserName:      "MyName",
		SecurityLevel: snmpgo.AuthPriv,
		AuthPassword:  "aaaaaaaa",
		AuthProtocol:  snmpgo.Md5,
		PrivPassword:  "bbbbbbbb",
	}
	err = snmpgo.ArgsValidate(args)
	if err == nil {
		t.Error("validate() - priv protocol")
	}

	args = &snmpgo.SNMPArguments{
		Version:       snmpgo.V3,
		UserName:      "MyName",
		SecurityLevel: snmpgo.AuthPriv,
		AuthPassword:  "aaaaaaaa",
		AuthProtocol:  snmpgo.Md5,
		PrivPassword:  "bbbbbbbb",
		PrivProtocol:  snmpgo.Des,
	}
	err = snmpgo.ArgsValidate(args)
	if err != nil {
		t.Errorf("validate() - has error %v", err)
	}
}

func TestSNMP(t *testing.T) {
	snmp, _ := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:       snmpgo.V3,
		UserName:      "MyName",
		SecurityLevel: snmpgo.AuthPriv,
		AuthPassword:  "aaaaaaaa",
		AuthProtocol:  snmpgo.Md5,
		PrivPassword:  "bbbbbbbb",
		PrivProtocol:  snmpgo.Des,
	})

	pdu := snmpgo.NewPdu(snmpgo.V3, snmpgo.Report)
	err := snmpgo.SnmpCheckPdu(snmp, pdu)
	if err != nil {
		t.Errorf("checkPdu() - has error %v", err)
	}

	oids, _ := snmpgo.NewOids([]string{"1.3.6.1.6.3.11.2.1.1.0"})
	pdu = snmpgo.NewPduWithOids(snmpgo.V3, snmpgo.Report, oids)
	err = snmpgo.SnmpCheckPdu(snmp, pdu)
	if err == nil {
		t.Error("checkPdu() - report oid")
	}
}
