package snmpgo_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/k-sone/snmpgo"
)

func TestMessageProcessingV1(t *testing.T) {
	snmp, _ := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:   snmpgo.V2c,
		Community: "public",
	})
	mp := snmpgo.NewMessageProcessing(snmp)
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
	expEngId := []byte{0x80, 0x00, 0x00, 0x00, 0x01}
	expCtxId := []byte{0x80, 0x00, 0x00, 0x00, 0x05}
	expCtxName := "myName"
	snmp, _ := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:         snmpgo.V3,
		UserName:        "myName",
		SecurityLevel:   snmpgo.AuthPriv,
		AuthPassword:    "aaaaaaaa",
		AuthProtocol:    snmpgo.Md5,
		PrivPassword:    "bbbbbbbb",
		PrivProtocol:    snmpgo.Des,
		ContextEngineId: hex.EncodeToString(expCtxId),
		ContextName:     expCtxName,
	})
	mp := snmpgo.NewMessageProcessing(snmp)
	usm := snmpgo.ToUsm(mp.Security())
	usm.AuthEngineId = expEngId
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
	p := pdu.(*snmpgo.ScopedPdu)
	if p.RequestId() == 0 {
		t.Error("PrepareOutgoingMessage() - request id")
	}
	if !bytes.Equal(p.ContextEngineId, expCtxId) {
		t.Errorf("PrepareOutgoingMessage() - expected [%s], actual [%s]",
			snmpgo.ToHexStr(expCtxId, ""), snmpgo.ToHexStr(p.ContextEngineId, ""))
	}
	if string(p.ContextName) != expCtxName {
		t.Errorf("GenerateRequestMessage() - expected [%s], actual [%s]",
			expCtxName, string(p.ContextName))
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
	rmsg.AuthEngineId = []byte{0, 0, 0, 0, 0}
	rmsg.UserName = []byte("myName")
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - message id check")
	}

	rmsg.MessageId = messageId
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Error("PrepareDataElements() - security model check")
	}

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
	if err == nil {
		t.Errorf("PrepareDataElements() - contextEngineId check")
	}

	pdu.(*snmpgo.ScopedPdu).ContextEngineId = expCtxId
	pduBytes, _ = pdu.Marshal()
	rmsg.SetPduBytes(pduBytes)
	b, _ = rmsg.Marshal()
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Errorf("PrepareDataElements() - contextName check")
	}

	pdu.(*snmpgo.ScopedPdu).ContextName = []byte(expCtxName)
	pduBytes, _ = pdu.Marshal()
	rmsg.SetPduBytes(pduBytes)
	b, _ = rmsg.Marshal()

	msgv3.SetAuthentication(true)
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err == nil {
		t.Errorf("PrepareDataElements() - response authenticate check")
	}

	msgv3.SetAuthentication(false)
	_, err = mp.PrepareDataElements(snmp, msg, b)
	if err != nil {
		t.Errorf("PrepareDataElements() - has error %v", err)
	}
}
