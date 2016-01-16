package snmpgo

import (
	"bytes"
	"fmt"
)

type messageProcessing interface {
	Security() security
	PrepareOutgoingMessage(*SNMP, Pdu) (message, error)
	PrepareDataElements(*SNMP, message, []byte) (Pdu, error)
}

type messageProcessingV1 struct {
	security *community
}

func (mp *messageProcessingV1) Security() security {
	return mp.security
}

func (mp *messageProcessingV1) PrepareOutgoingMessage(
	snmp *SNMP, pdu Pdu) (msg message, err error) {

	_, ok := pdu.(*PduV1)
	if !ok {
		return nil, &ArgumentError{
			Value:   pdu,
			Message: "Type of Pdu is not PduV1",
		}
	}
	pdu.SetRequestId(genRequestId())
	msg = newMessage(snmp.args.Version, pdu)

	err = mp.security.GenerateRequestMessage(msg)
	return
}

func (mp *messageProcessingV1) PrepareDataElements(
	snmp *SNMP, sendMsg message, b []byte) (Pdu, error) {

	pdu := &PduV1{}
	recvMsg := newMessage(snmp.args.Version, pdu)
	_, err := recvMsg.Unmarshal(b)
	if err != nil {
		return nil, &ResponseError{
			Cause:   err,
			Message: "Failed to Unmarshal message",
			Detail:  fmt.Sprintf("message Bytes - [%s]", toHexStr(b, " ")),
		}
	}

	if sendMsg.Version() != recvMsg.Version() {
		return nil, &ResponseError{
			Message: fmt.Sprintf(
				"SNMPVersion mismatch - expected [%v], actual [%v]",
				sendMsg.Version(), recvMsg.Version()),
			Detail: fmt.Sprintf("%s vs %s", sendMsg, recvMsg),
		}
	}

	err = mp.security.ProcessIncomingMessage(recvMsg)
	if err != nil {
		return nil, err
	}

	if pdu.PduType() != GetResponse {
		return nil, &ResponseError{
			Message: fmt.Sprintf("Illegal PduType - expected [%s], actual [%v]",
				GetResponse, pdu.PduType()),
		}
	}
	if sendMsg.Pdu().RequestId() != pdu.RequestId() {
		return nil, &ResponseError{
			Message: fmt.Sprintf("RequestId mismatch - expected [%d], actual [%d]",
				sendMsg.Pdu().RequestId(), pdu.RequestId()),
			Detail: fmt.Sprintf("%s vs %s", sendMsg, recvMsg),
		}
	}
	return pdu, nil
}

type messageProcessingV3 struct {
	security *usm
}

func (mp *messageProcessingV3) Security() security {
	return mp.security
}

func (mp *messageProcessingV3) PrepareOutgoingMessage(
	snmp *SNMP, pdu Pdu) (msg message, err error) {

	p, ok := pdu.(*ScopedPdu)
	if !ok {
		return nil, &ArgumentError{
			Value:   pdu,
			Message: "Type of Pdu is not ScopedPdu",
		}
	}
	p.SetRequestId(genRequestId())
	if snmp.args.ContextEngineId != "" {
		p.ContextEngineId, _ = engineIdToBytes(snmp.args.ContextEngineId)
	} else {
		p.ContextEngineId = mp.security.AuthEngineId
	}
	if snmp.args.ContextName != "" {
		p.ContextName = []byte(snmp.args.ContextName)
	}

	msg = newMessage(snmp.args.Version, pdu)
	m := msg.(*messageV3)
	m.MessageId = genMessageId()
	m.MessageMaxSize = snmp.args.MessageMaxSize
	m.SecurityModel = securityUsm
	m.SetReportable(confirmedType(pdu.PduType()))
	if snmp.args.SecurityLevel >= AuthNoPriv {
		m.SetAuthentication(true)
		if snmp.args.SecurityLevel >= AuthPriv {
			m.SetPrivacy(true)
		}
	}

	err = mp.security.GenerateRequestMessage(msg)
	return
}

func (mp *messageProcessingV3) PrepareDataElements(
	snmp *SNMP, sendMsg message, b []byte) (Pdu, error) {

	pdu := &ScopedPdu{}
	recvMsg := newMessage(snmp.args.Version, pdu)
	_, err := recvMsg.Unmarshal(b)
	if err != nil {
		return nil, &ResponseError{
			Cause:   err,
			Message: "Failed to Unmarshal message",
			Detail:  fmt.Sprintf("message Bytes - [%s]", toHexStr(b, " ")),
		}
	}

	sm := sendMsg.(*messageV3)
	rm := recvMsg.(*messageV3)
	if sm.Version() != rm.Version() {
		return nil, &ResponseError{
			Message: fmt.Sprintf(
				"SNMPVersion mismatch - expected [%v], actual [%v]", sm.Version(), rm.Version()),
			Detail: fmt.Sprintf("%s vs %s", sm, rm),
		}
	}
	if sm.MessageId != rm.MessageId {
		return nil, &ResponseError{
			Message: fmt.Sprintf(
				"MessageId mismatch - expected [%d], actual [%d]", sm.MessageId, rm.MessageId),
			Detail: fmt.Sprintf("%s vs %s", sm, rm),
		}
	}
	if rm.SecurityModel != securityUsm {
		return nil, &ResponseError{
			Message: fmt.Sprintf("Unknown SecurityModel, value [%d]", rm.SecurityModel),
		}
	}

	err = mp.security.ProcessIncomingMessage(recvMsg)
	if err != nil {
		return nil, err
	}

	switch t := pdu.PduType(); t {
	case GetResponse:
		if sm.Pdu().RequestId() != pdu.RequestId() {
			return nil, &ResponseError{
				Message: fmt.Sprintf("RequestId mismatch - expected [%d], actual [%d]",
					sm.Pdu().RequestId(), pdu.RequestId()),
				Detail: fmt.Sprintf("%s vs %s", sm, rm),
			}
		}

		sPdu := sm.Pdu().(*ScopedPdu)
		if !bytes.Equal(sPdu.ContextEngineId, pdu.ContextEngineId) {
			return nil, &ResponseError{
				Message: fmt.Sprintf("ContextEngineId mismatch - expected [%s], actual [%s]",
					toHexStr(sPdu.ContextEngineId, ""), toHexStr(pdu.ContextEngineId, "")),
			}
		}

		if !bytes.Equal(sPdu.ContextName, pdu.ContextName) {
			return nil, &ResponseError{
				Message: fmt.Sprintf("ContextName mismatch - expected [%s], actual [%s]",
					toHexStr(sPdu.ContextName, ""), toHexStr(pdu.ContextName, "")),
			}
		}

		if sm.Authentication() && !rm.Authentication() {
			return nil, &ResponseError{
				Message: "Response message is not authenticated",
			}
		}
	case Report:
		if sm.Reportable() {
			break
		}
		fallthrough
	default:
		return nil, &ResponseError{
			Message: fmt.Sprintf("Illegal PduType - expected [%s], actual [%v]", GetResponse, t),
		}
	}

	return pdu, nil
}

func newMessageProcessing(snmp *SNMP) (mp messageProcessing) {
	switch snmp.args.Version {
	case V1, V2c:
		mp = &messageProcessingV1{
			security: &community{
				Community: []byte(snmp.args.Community),
			},
		}
	case V3:
		mp = &messageProcessingV3{
			security: &usm{
				UserName:     []byte(snmp.args.UserName),
				AuthPassword: snmp.args.AuthPassword,
				AuthProtocol: snmp.args.AuthProtocol,
				PrivPassword: snmp.args.PrivPassword,
				PrivProtocol: snmp.args.PrivProtocol,
			},
		}
	}
	return
}
