package snmpgo_test

import (
	"bytes"
	"testing"

	"github.com/k-sone/snmpgo"
)

func TestMessageV1(t *testing.T) {
	pdu := snmpgo.NewPdu(snmpgo.V2c, snmpgo.GetRequest)
	msg := snmpgo.ToMessageV1(snmpgo.NewMessage(snmpgo.V2c, pdu))
	b, _ := pdu.Marshal()
	msg.SetPduBytes(b)
	msg.Community = []byte("MyCommunity")

	expBuf := []byte{
		0x30, 0x1d, 0x02, 0x01, 0x01, 0x04, 0x0b, 0x4d, 0x79, 0x43, 0x6f,
		0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x74, 0x79, 0xa0, 0x0b, 0x02, 0x01,
		0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
	}
	buf, err := msg.Marshal()
	if err != nil {
		t.Fatal("Marshal() : %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpgo.ToHexStr(expBuf, " "), snmpgo.ToHexStr(buf, " "))
	}

	expStr := `{"Version": "2c", "Community": "MyCommunity", ` +
		`"Pdu": {"Type": "GetRequest", "RequestId": "0", "ErrorStatus": ` +
		`"NoError", "ErrorIndex": "0", "VarBinds": []}}`
	m := snmpgo.NewMessage(snmpgo.V2c, pdu)
	rest, err := m.Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != m.String() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, m.String())
	}
}

func TestMessageV3(t *testing.T) {
	pdu := snmpgo.NewPdu(snmpgo.V3, snmpgo.GetRequest)
	msg := snmpgo.ToMessageV3(snmpgo.NewMessage(snmpgo.V3, pdu))
	b, _ := pdu.Marshal()
	msg.SetPduBytes(b)
	msg.MessageId = 123
	msg.MessageMaxSize = 321
	msg.SetReportable(true)
	msg.SetPrivacy(true)
	msg.SetAuthentication(true)
	msg.SecurityModel = 3
	msg.AuthEngineId = []byte{0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	msg.AuthEngineBoots = 456
	msg.AuthEngineTime = 654
	msg.UserName = []byte("User")
	msg.AuthParameter = []byte{0xaa, 0xbb, 0xcc}
	msg.PrivParameter = []byte{0xdd, 0xee, 0xff}

	expBuf := []byte{
		0x30, 0x4b, 0x02, 0x01, 0x03, 0x30, 0x0d, 0x02, 0x01, 0x7b,
		0x02, 0x02, 0x01, 0x41, 0x04, 0x01, 0x07, 0x02, 0x01, 0x03,
		0x04, 0x24, 0x30, 0x22, 0x04, 0x08, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x02, 0x02, 0x01, 0xc8, 0x02, 0x02, 0x02, 0x8e, 0x04, 0x04, 0x55, 0x73, 0x65, 0x72,
		0x04, 0x03, 0xaa, 0xbb, 0xcc, 0x04, 0x03, 0xdd, 0xee, 0xff,
		0x30, 0x11, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0b, 0x02, 0x01,
		0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
	}

	buf, err := msg.Marshal()
	if err != nil {
		t.Fatal("Marshal() : %v", err)
	}
	if !bytes.Equal(expBuf, buf) {
		t.Errorf("Marshal() - expected [%s], actual [%s]",
			snmpgo.ToHexStr(expBuf, " "), snmpgo.ToHexStr(buf, " "))
	}

	expStr := `{"Version": "3", "GlobalData": {"MessageId": "123", "MessageMaxSize": "321", ` +
		`"MessageFlags": "apr", "SecurityModel": "USM"}, "SecurityParameter": ` +
		`{"AuthEngineId": "8001020304050607", "AuthEngineBoots": "456", ` +
		`"AuthEngineTime": "654", "UserName": "User", "AuthParameter": "aa:bb:cc", ` +
		`"PrivParameter": "dd:ee:ff"}, "Pdu": {"Type": "GetRequest", "RequestId": "0", ` +
		`"ErrorStatus": "NoError", "ErrorIndex": "0", "ContextEngineId": "", ` +
		`"ContextName": "", "VarBinds": []}}`
	m := snmpgo.NewMessage(snmpgo.V3, pdu)
	rest, err := m.Unmarshal(buf)
	if len(rest) != 0 || err != nil {
		t.Errorf("Unmarshal() - len[%d] err[%v]", len(rest), err)
	}
	if expStr != m.String() {
		t.Errorf("Unmarshal() - expected [%s], actual [%s]", expStr, m.String())
	}
}

func TestMessageProcessingV1(t *testing.T) {
	snmp, _ := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:   snmpgo.V2c,
		Community: "public",
	})
	mp := snmpgo.NewMessageProcessing(snmpgo.V2c)
	pdu := snmpgo.NewPdu(snmpgo.V2c, snmpgo.GetRequest)

	msg, err := mp.PrepareOutgoingMessage(snmp, pdu)
	if err != nil {
		t.Errorf("PrepareOutgoingMessage() - has error %v", err)
	}
	if len(msg.PduBytes()) == 0 {
		t.Error("PrepareOutgoingMessage() - pdu bytes")
	}
	if pdu.RequestId() == 0 {
		t.Error("PrepareOutgoingMessage() - request id")
	}
	requestId := pdu.RequestId()

	_, err = mp.PrepareDataElements(snmp, msg, []byte{0x00, 0x00})
	if err == nil {
		t.Error("PrepareDataElements() - message unmarshal error")
	}

	b, _ := msg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - pdu type check")
	}

	pdu = snmpgo.NewPdu(snmpgo.V2c, snmpgo.GetResponse)
	rmsg := snmpgo.ToMessageV1(snmpgo.NewMessage(snmpgo.V1, pdu))
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - version check")
	}

	pdu.SetRequestId(requestId)
	pduBytes, _ := pdu.Marshal()
	rmsg = snmpgo.ToMessageV1(snmpgo.NewMessage(snmpgo.V2c, pdu))
	rmsg.Community = []byte("public")
	rmsg.SetPduBytes(pduBytes)
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err != nil {
		t.Errorf("PrepareDataElements() - has error %v", err)
	}
}

func TestMessageProcessingV3(t *testing.T) {
	snmp, _ := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:       snmpgo.V3,
		UserName:      "myName",
		SecurityLevel: snmpgo.AuthPriv,
		AuthPassword:  "aaaaaaaa",
		AuthProtocol:  snmpgo.Md5,
		PrivPassword:  "bbbbbbbb",
		PrivProtocol:  snmpgo.Des,
	})
	mp := snmpgo.NewMessageProcessing(snmpgo.V3)
	usm := snmpgo.ToUsm(mp.Security())
	usm.AuthKey = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	usm.PrivKey = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	pdu := snmpgo.NewPdu(snmpgo.V3, snmpgo.GetRequest)

	msg, err := mp.PrepareOutgoingMessage(snmp, pdu)
	if err != nil {
		t.Errorf("PrepareOutgoingMessage() - has error %v", err)
	}
	if len(msg.PduBytes()) == 0 {
		t.Error("PrepareOutgoingMessage() - pdu bytes")
	}
	if pdu.RequestId() == 0 {
		t.Error("PrepareOutgoingMessage() - request id")
	}
	msgv3 := snmpgo.ToMessageV3(msg)
	if msgv3.MessageId == 0 {
		t.Error("PrepareOutgoingMessage() - message id")
	}
	if !msgv3.Reportable() || !msgv3.Authentication() || !msgv3.Privacy() {
		t.Error("PrepareOutgoingMessage() - security flag")
	}
	msgv3.SetAuthentication(false)
	msgv3.SetPrivacy(false)
	msgv3.AuthEngineId = []byte{0, 0, 0, 0, 0}
	requestId := pdu.RequestId()
	messageId := msgv3.MessageId

	_, err = mp.PrepareDataElements(snmp, msg, []byte{0x00, 0x00})
	if err == nil {
		t.Error("PrepareDataElements() - message unmarshal error")
	}

	b, _ := msg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - pdu type check")
	}

	pdu = snmpgo.NewPdu(snmpgo.V3, snmpgo.GetResponse)
	rmsg := snmpgo.ToMessageV3(snmpgo.NewMessage(snmpgo.V3, pdu))
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - message id check")
	}

	rmsg = snmpgo.ToMessageV3(snmpgo.NewMessage(snmpgo.V3, pdu))
	rmsg.AuthEngineId = []byte{0, 0, 0, 0, 0}
	rmsg.MessageId = messageId
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - security model check")
	}

	pdu.(*snmpgo.ScopedPdu).ContextEngineId = rmsg.AuthEngineId
	pduBytes, _ := pdu.Marshal()
	rmsg.SetPduBytes(pduBytes)
	rmsg.SecurityModel = 3
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - request id check")
	}

	pdu.SetRequestId(requestId)
	pduBytes, _ = pdu.Marshal()
	rmsg.SetPduBytes(pduBytes)
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err != nil {
		t.Errorf("PrepareDataElements() - has error %v", err)
	}
}
