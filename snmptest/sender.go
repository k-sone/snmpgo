package snmptest

import (
	"testing"

	"github.com/k-sone/snmpgo"
)

type TrapSender struct {
	t       *testing.T
	Address string
}

func NewTrapSender(t *testing.T, address string) *TrapSender {
	return &TrapSender{t: t, Address: address}
}

func (t *TrapSender) SendV2TrapWithBindings(trap bool, community string, v snmpgo.VarBinds) {
	snmp, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:   snmpgo.V2c,
		Address:   t.Address,
		Network:   "udp4",
		Retries:   1,
		Community: community,
	})
	if err != nil {
		// Failed to create SNMP object
		t.t.Fatal(err)
		return
	}

	if err = snmp.Open(); err != nil {
		// Failed to open connection
		t.t.Fatal(err)
		return
	}

	defer snmp.Close()

	if trap {
		err = snmp.V2Trap(v)
	} else {
		err = snmp.InformRequest(v)
	}

	if err != nil {
		// Failed to request
		t.t.Fatal(err)
		return
	}

}

// NewTrapServer creates a new Trap Server & Serve
func NewTrapServer(address string, listener snmpgo.TrapListener) *snmpgo.TrapServer {
	s, _ := snmpgo.NewTrapServer(snmpgo.ServerArguments{
		LocalAddr: address,
	})
	s.AddSecurity(&snmpgo.SecurityEntry{
		Version:   snmpgo.V2c,
		Community: "public",
	})

	ch := make(chan struct{}, 0)
	go func() {
		ch <- struct{}{}
		s.Serve(listener)
	}()
	<-ch
	return s
}
