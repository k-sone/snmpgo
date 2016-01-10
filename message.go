package snmpgo

import (
	"encoding/asn1"
	"fmt"
)

type message interface {
	Version() SNMPVersion
	Pdu() Pdu
	PduBytes() []byte
	SetPduBytes([]byte)
	Marshal() ([]byte, error)
	Unmarshal([]byte) ([]byte, error)
	String() string
}

type messageV1 struct {
	version   SNMPVersion
	Community []byte
	pduBytes  []byte
	pdu       Pdu
}

func (msg *messageV1) Version() SNMPVersion {
	return msg.version
}

func (msg *messageV1) Pdu() Pdu {
	return msg.pdu
}

func (msg *messageV1) PduBytes() []byte {
	return msg.pduBytes
}

func (msg *messageV1) SetPduBytes(b []byte) {
	msg.pduBytes = b
}

func (msg *messageV1) Marshal() (b []byte, err error) {
	var buf []byte
	raw := asn1.RawValue{Class: classUniversal, Tag: tagSequence, IsCompound: true}

	buf, err = asn1.Marshal(msg.version)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = asn1.Marshal(msg.Community)
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	raw.Bytes = append(raw.Bytes, msg.pduBytes...)
	return asn1.Marshal(raw)
}

func (msg *messageV1) Unmarshal(b []byte) (rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(b, &raw)
	if err != nil {
		return
	}
	if raw.Class != classUniversal || raw.Tag != tagSequence || !raw.IsCompound {
		return nil, asn1.StructuralError{fmt.Sprintf(
			"Invalid messageV1 object - Class [%02x], Tag [%02x] : [%s]",
			raw.Class, raw.Tag, toHexStr(b, " "))}
	}

	next := raw.Bytes

	var version int
	next, err = asn1.Unmarshal(next, &version)
	if err != nil {
		return
	}

	var community []byte
	next, err = asn1.Unmarshal(next, &community)
	if err != nil {
		return
	}

	msg.version = SNMPVersion(version)
	msg.Community = community
	msg.pduBytes = next
	return
}

func (msg *messageV1) String() string {
	return fmt.Sprintf(
		`{"Version": "%s", "Community": "%s", "Pdu": %s}`,
		msg.version, msg.Community, msg.pdu.String())
}

type securityModel int

const (
	securityUsm = 3
)

func (s securityModel) String() string {
	switch s {
	case securityUsm:
		return "USM"
	default:
		return "Unknown"
	}
}

type globalDataV3 struct {
	MessageId      int
	MessageMaxSize int
	MessageFlags   []byte
	SecurityModel  securityModel
}

func (h *globalDataV3) Marshal() (b []byte, err error) {
	return asn1.Marshal(*h)
}

func (h *globalDataV3) Unmarshal(b []byte) (rest []byte, err error) {
	return asn1.Unmarshal(b, h)
}

func (h *globalDataV3) initFlags() {
	if len(h.MessageFlags) == 0 {
		h.MessageFlags = append(h.MessageFlags, 0)
	}
}

func (h *globalDataV3) SetReportable(b bool) {
	h.initFlags()
	if b {
		h.MessageFlags[0] |= 0x04
	} else {
		h.MessageFlags[0] &= 0xfb
	}
}

func (h *globalDataV3) Reportable() bool {
	h.initFlags()
	if h.MessageFlags[0]&0x04 == 0 {
		return false
	}
	return true
}

func (h *globalDataV3) SetPrivacy(b bool) {
	h.initFlags()
	if b {
		h.MessageFlags[0] |= 0x02
	} else {
		h.MessageFlags[0] &= 0xfd
	}
}

func (h *globalDataV3) Privacy() bool {
	h.initFlags()
	if h.MessageFlags[0]&0x02 == 0 {
		return false
	}
	return true
}

func (h *globalDataV3) SetAuthentication(b bool) {
	h.initFlags()
	if b {
		h.MessageFlags[0] |= 0x01
	} else {
		h.MessageFlags[0] &= 0xfe
	}
}

func (h *globalDataV3) Authentication() bool {
	h.initFlags()
	if h.MessageFlags[0]&0x01 == 0 {
		return false
	}
	return true
}

func (h *globalDataV3) String() string {
	var flags string
	if h.Authentication() {
		flags += "a"
	}
	if h.Privacy() {
		flags += "p"
	}
	if h.Reportable() {
		flags += "r"
	}

	return fmt.Sprintf(
		`{"MessageId": "%d", "MessageMaxSize": "%d", "MessageFlags": "%s", `+
			`"SecurityModel": "%s"}`,
		h.MessageId, h.MessageMaxSize, flags, h.SecurityModel)
}

type securityParameterV3 struct {
	AuthEngineId    []byte
	AuthEngineBoots int64
	AuthEngineTime  int64
	UserName        []byte
	AuthParameter   []byte
	PrivParameter   []byte
}

func (sec *securityParameterV3) Marshal() ([]byte, error) {
	raw := asn1.RawValue{Class: classUniversal, Tag: tagOctetString, IsCompound: false}

	buf, err := asn1.Marshal(*sec)
	if err != nil {
		return nil, err
	}
	raw.Bytes = buf

	return asn1.Marshal(raw)
}

func (sec *securityParameterV3) Unmarshal(b []byte) (rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(b, &raw)
	if err != nil {
		return
	}

	if raw.Class != classUniversal || raw.Tag != tagOctetString || raw.IsCompound {
		return nil, asn1.StructuralError{fmt.Sprintf(
			"Invalid SecurityParameter object - Class [%02x], Tag [%02x] : [%s]",
			raw.Class, raw.Tag, toHexStr(b, " "))}
	}

	_, err = asn1.Unmarshal(raw.Bytes, sec)
	return
}

func (sec *securityParameterV3) String() string {
	return fmt.Sprintf(
		`{"AuthEngineId": "%s", "AuthEngineBoots": "%d", "AuthEngineTime": "%d", `+
			`"UserName": "%s", "AuthParameter": "%s", "PrivParameter": "%s"}`,
		toHexStr(sec.AuthEngineId, ""), sec.AuthEngineBoots, sec.AuthEngineTime, sec.UserName,
		toHexStr(sec.AuthParameter, ":"), toHexStr(sec.PrivParameter, ":"))
}

type messageV3 struct {
	globalDataV3
	securityParameterV3
	messageV1
}

func (msg *messageV3) Marshal() (b []byte, err error) {
	var buf []byte
	raw := asn1.RawValue{Class: classUniversal, Tag: tagSequence, IsCompound: true}

	buf, err = asn1.Marshal(msg.version)
	if err != nil {
		return
	}
	raw.Bytes = buf

	buf, err = msg.globalDataV3.Marshal()
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	buf, err = msg.securityParameterV3.Marshal()
	if err != nil {
		return
	}
	raw.Bytes = append(raw.Bytes, buf...)

	raw.Bytes = append(raw.Bytes, msg.pduBytes...)
	return asn1.Marshal(raw)
}

func (msg *messageV3) Unmarshal(b []byte) (rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(b, &raw)
	if err != nil {
		return nil, err
	}
	if raw.Class != classUniversal || raw.Tag != tagSequence || !raw.IsCompound {
		return nil, asn1.StructuralError{fmt.Sprintf(
			"Invalid messageV3 object - Class [%02x], Tag [%02x] : [%s]",
			raw.FullBytes[0], tagSequence, toHexStr(b, " "))}
	}

	next := raw.Bytes

	var version int
	next, err = asn1.Unmarshal(next, &version)
	if err != nil {
		return
	}

	next, err = msg.globalDataV3.Unmarshal(next)
	if err != nil {
		return
	}

	next, err = msg.securityParameterV3.Unmarshal(next)
	if err != nil {
		return
	}

	msg.version = SNMPVersion(version)
	msg.pduBytes = next
	return
}

func (msg *messageV3) String() string {
	return fmt.Sprintf(
		`{"Version": "%s", "GlobalData": %s, "SecurityParameter": %s, "Pdu": %s}`,
		msg.version, msg.globalDataV3.String(), msg.securityParameterV3.String(),
		msg.pdu.String())
}

func newMessage(ver SNMPVersion, pdu Pdu) (msg message) {
	m := messageV1{
		version: ver,
		pdu:     pdu,
	}
	switch ver {
	case V1, V2c:
		msg = &m
	case V3:
		msg = &messageV3{
			messageV1:    m,
			globalDataV3: globalDataV3{MessageFlags: []byte{0}},
		}
	}
	return
}

type messageProcessing interface {
	Security() security
	PrepareOutgoingMessage(*SNMP, Pdu) (message, error)
	PrepareDataElements(*SNMP, message, []byte) (Pdu, error)
}

type messageProcessingV1 struct {
	security security
}

func (mp *messageProcessingV1) Security() security {
	return mp.security
}

func (mp *messageProcessingV1) PrepareOutgoingMessage(
	snmp *SNMP, pdu Pdu) (msg message, err error) {

	pdu.SetRequestId(genRequestId())
	msg = newMessage(snmp.args.Version, pdu)

	err = mp.security.GenerateRequestMessage(snmp, msg)
	return
}

func (mp *messageProcessingV1) PrepareDataElements(
	snmp *SNMP, sendMsg message, b []byte) (pdu Pdu, err error) {

	pdu = &PduV1{}
	recvMsg := newMessage(snmp.args.Version, pdu)
	_, err = recvMsg.Unmarshal(b)
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

	err = mp.security.ProcessIncomingMessage(snmp, sendMsg, recvMsg)
	if err != nil {
		return nil, err
	}

	if recvMsg.Pdu().PduType() != GetResponse {
		return nil, &ResponseError{
			Message: fmt.Sprintf("Illegal PduType - expected [%s], actual [%v]",
				GetResponse, recvMsg.Pdu().PduType()),
		}
	}
	if sendMsg.Pdu().RequestId() != recvMsg.Pdu().RequestId() {
		return nil, &ResponseError{
			Message: fmt.Sprintf("RequestId mismatch - expected [%d], actual [%d]",
				sendMsg.Pdu().RequestId(), recvMsg.Pdu().RequestId()),
			Detail: fmt.Sprintf("%s vs %s", sendMsg, recvMsg),
		}
	}
	return
}

type messageProcessingV3 struct {
	security security
}

func (mp *messageProcessingV3) Security() security {
	return mp.security
}

func (mp *messageProcessingV3) PrepareOutgoingMessage(
	snmp *SNMP, pdu Pdu) (msg message, err error) {

	pdu.SetRequestId(genRequestId())
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

	err = mp.security.GenerateRequestMessage(snmp, msg)
	return
}

func (mp *messageProcessingV3) PrepareDataElements(
	snmp *SNMP, sendMsg message, b []byte) (pdu Pdu, err error) {

	pdu = &ScopedPdu{}
	recvMsg := newMessage(snmp.args.Version, pdu)
	_, err = recvMsg.Unmarshal(b)
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

	err = mp.security.ProcessIncomingMessage(snmp, sendMsg, recvMsg)
	if err != nil {
		return nil, err
	}

	switch t := rm.Pdu().PduType(); t {
	case GetResponse:
		if sm.Pdu().RequestId() != rm.Pdu().RequestId() {
			return nil, &ResponseError{
				Message: fmt.Sprintf("RequestId mismatch - expected [%d], actual [%d]",
					sm.Pdu().RequestId(), rm.Pdu().RequestId()),
				Detail: fmt.Sprintf("%s vs %s", sm, rm),
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

	return
}

func newMessageProcessing(ver SNMPVersion) (mp messageProcessing) {
	switch ver {
	case V1, V2c:
		mp = &messageProcessingV1{security: &community{}}
	case V3:
		mp = &messageProcessingV3{security: &usm{}}
	}
	return
}
