package snmpgo_test

import (
	"reflect"
	"testing"

	"github.com/k-sone/snmpgo"
	"github.com/k-sone/snmpgo/snmptest"
)

type receiveQueue struct {
	msg chan *snmpgo.TrapRequest
}

func (t *receiveQueue) OnTRAP(trap *snmpgo.TrapRequest) {
	t.msg <- trap
}

// takeNextTrap blocks till next trap is received
func (n *receiveQueue) takeNextTrap() *snmpgo.TrapRequest {
	return <-n.msg
}

func TestSendV2TrapAndReceiveIt(t *testing.T) {
	trapQueue := &receiveQueue{make(chan *snmpgo.TrapRequest)}
	trapSender := snmptest.NewTrapSender(t)

	s, _ := snmptest.NewServer("localhost:5000", trapQueue)
	defer s.Close()

	var varBinds snmpgo.VarBinds
	oid, _ := snmpgo.NewOid("1.3.6.1.6.3.1.1.5.3")
	varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSnmpTrap, oid))

	trapSender.SendV2TrapWithBindings(varBinds)

	trap := trapQueue.takeNextTrap()
	pdu := trap.Message.Pdu()

	if pdu.PduType() != snmpgo.SNMPTrapV2 {
		t.Fatalf("expected trapv2, got: %s", pdu.PduType())
	}

	if !reflect.DeepEqual(pdu.VarBinds(), varBinds) {
		t.Fatalf("expected pdu bindings %v, got %v", varBinds, pdu.VarBinds())
	}
}

func TestCollectMultipleTraps(t *testing.T) {
	trapQueue := &receiveQueue{make(chan *snmpgo.TrapRequest)}
	trapSender := snmptest.NewTrapSender(t)

	s, _ := snmptest.NewServer("localhost:5000", trapQueue)
	defer s.Close()

	var varBinds snmpgo.VarBinds
	oid, _ := snmpgo.NewOid("1.3.6.1.6.3.1.1.5.3")
	varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSnmpTrap, oid))

	trapSender.SendV2TrapWithBindings(varBinds)
	trapSender.SendV2TrapWithBindings(varBinds)
	trapSender.SendV2TrapWithBindings(varBinds)

	//TODO(mgenov): use deadline when checking such cases cause test deadline is really long
	// will block forever if traps are not received
	for i := 0; i < 3; i++ {
		trapQueue.takeNextTrap()
	}
}
