package snmptest

import (
	"net"
	"testing"

	"github.com/k-sone/snmpgo"
)

type TrapSender struct {
	t       *testing.T
	Address string
}

func NewTrapSender(t *testing.T) *TrapSender {
	return &TrapSender{t: t, Address: "localhost:5000"}
}

func (t *TrapSender) SendV2TrapWithBindings(v snmpgo.VarBinds) {
	snmp, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:   snmpgo.V2c,
		Address:   t.Address,
		Network:   "udp4",
		Retries:   1,
		Community: "public",
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

	if err = snmp.V2Trap(v); err != nil {
		// Failed to request
		t.t.Fatal(err)
		return
	}

}

// Server is a testing Trap server
type Server struct {
	l net.Conn
	*snmpgo.Server
}

// NewServer creates a new Trap Server
func NewServer(address string, listener snmpgo.TrapListener) (*Server, error) {
	s := &snmpgo.Server{}
	addr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return nil, err
	}

	l, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}
	go s.Serve(l, listener)

	return &Server{l, s}, nil
}

func (s *Server) Close() {
	s.l.Close()
}
