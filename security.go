package snmpgo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"time"
)

type security interface {
	GenerateRequestMessage(*SNMP, message) error
	ProcessIncomingMessage(*SNMP, message, message) error
	Discover(*SNMP) error
	String() string
}

type community struct{}

func (c *community) GenerateRequestMessage(snmp *SNMP, sendMsg message) (err error) {
	m := sendMsg.(*messageV1)
	m.Community = []byte(snmp.args.Community)

	b, err := m.Pdu().Marshal()
	if err != nil {
		return
	}
	m.SetPduBytes(b)

	return
}

func (c *community) ProcessIncomingMessage(snmp *SNMP, sendMsg, recvMsg message) (err error) {
	sm := sendMsg.(*messageV1)
	rm := recvMsg.(*messageV1)

	if !bytes.Equal(sm.Community, rm.Community) {
		return ResponseError{
			Message: fmt.Sprintf(
				"Community mismatch - expected [%s], actual [%s]",
				string(sm.Community), string(rm.Community)),
			Detail: fmt.Sprintf("%s vs %s", sm, rm),
		}
	}

	_, err = rm.Pdu().Unmarshal(rm.PduBytes())
	if err != nil {
		return ResponseError{
			Cause:   err,
			Message: "Failed to Unmarshal Pdu",
			Detail:  fmt.Sprintf("Pdu Bytes - [%s]", toHexStr(rm.PduBytes(), " ")),
		}
	}
	return
}

func (c *community) Discover(snmp *SNMP) error {
	return nil
}

func (c *community) String() string {
	return "{}"
}

type discoveryStatus int

const (
	noDiscovered discoveryStatus = iota
	noSynchronized
	discovered
)

func (d discoveryStatus) String() string {
	switch d {
	case noDiscovered:
		return "noDiscovered"
	case noSynchronized:
		return "noSynchronized"
	case discovered:
		return "discovered"
	default:
		return "Unknown"
	}
}

type usm struct {
	DiscoveryStatus discoveryStatus
	AuthEngineId    []byte
	AuthEngineBoots int64
	AuthEngineTime  int64
	AuthKey         []byte
	PrivKey         []byte
	UpdatedTime     time.Time
}

func (u *usm) GenerateRequestMessage(snmp *SNMP, sendMsg message) (err error) {
	// setup message
	m := sendMsg.(*messageV3)

	if u.DiscoveryStatus > noDiscovered {
		m.UserName = []byte(snmp.args.UserName)
		m.AuthEngineId = u.AuthEngineId
	}
	if u.DiscoveryStatus > noSynchronized {
		err = u.UpdateEngineBootsTime()
		if err != nil {
			return
		}
		m.AuthEngineBoots = u.AuthEngineBoots
		m.AuthEngineTime = u.AuthEngineTime
	}

	// setup Pdu
	p := sendMsg.Pdu().(*ScopedPdu)

	if snmp.args.ContextEngineId != "" {
		p.ContextEngineId, _ = engineIdToBytes(snmp.args.ContextEngineId)
	} else {
		p.ContextEngineId = m.AuthEngineId
	}
	if snmp.args.ContextName != "" {
		p.ContextName = []byte(snmp.args.ContextName)
	}

	pduBytes, err := p.Marshal()
	if err != nil {
		return
	}
	m.SetPduBytes(pduBytes)

	if m.Authentication() {
		// encrypt Pdu
		if m.Privacy() {
			err = encrypt(m, snmp.args.PrivProtocol, u.PrivKey)
			if err != nil {
				return
			}
		}

		// get digest of whole message
		digest, e := mac(m, snmp.args.AuthProtocol, u.AuthKey)
		if e != nil {
			return e
		}
		m.AuthParameter = digest
	}

	return
}

func (u *usm) ProcessIncomingMessage(snmp *SNMP, sendMsg, recvMsg message) (err error) {
	sm := sendMsg.(*messageV3)
	rm := recvMsg.(*messageV3)

	// RFC3411 Section 5
	if l := len(rm.AuthEngineId); l < 5 || l > 32 {
		return ResponseError{
			Message: fmt.Sprintf("AuthEngineId length is range 5..32, value [%s]",
				toHexStr(rm.AuthEngineId, "")),
		}
	}
	if rm.AuthEngineBoots < 0 || rm.AuthEngineBoots > math.MaxInt32 {
		return ResponseError{
			Message: fmt.Sprintf("AuthEngineBoots is range %d..%d, value [%d]",
				0, math.MaxInt32, rm.AuthEngineBoots),
		}
	}
	if rm.AuthEngineTime < 0 || rm.AuthEngineTime > math.MaxInt32 {
		return ResponseError{
			Message: fmt.Sprintf("AuthEngineTime is range %d..%d, value [%d]",
				0, math.MaxInt32, rm.AuthEngineTime),
		}
	}
	if !bytes.Equal(sm.UserName, rm.UserName) {
		return ResponseError{
			Message: fmt.Sprintf(
				"UserName mismatch - expected [%s], actual[%s]",
				string(sm.UserName), string(rm.UserName)),
			Detail: fmt.Sprintf("%s vs %s", sm, rm),
		}
	}

	if rm.Authentication() {
		// get & check digest of whole message
		digest, e := mac(rm, snmp.args.AuthProtocol, u.AuthKey)
		if e != nil {
			return ResponseError{
				Cause:   e,
				Message: "Can't get a message digest",
			}
		}
		if !hmac.Equal(rm.AuthParameter, digest) {
			return ResponseError{
				Message: fmt.Sprintf("Failed to authenticate - expected [%s], actual [%s]",
					toHexStr(rm.AuthParameter, ""), toHexStr(digest, "")),
			}
		}

		// decrypt Pdu
		if rm.Privacy() {
			e := decrypt(rm, snmp.args.PrivProtocol, u.PrivKey, rm.PrivParameter)
			if e != nil {
				return ResponseError{
					Cause:   e,
					Message: "Can't decrypt a message",
				}
			}
		}
	}

	// update boots & time
	switch u.DiscoveryStatus {
	case discovered:
		if rm.Authentication() {
			err = u.CheckTimeliness(rm.AuthEngineBoots, rm.AuthEngineTime)
			if err != nil {
				u.SynchronizeEngineBootsTime(0, 0)
				u.DiscoveryStatus = noSynchronized
				return
			}
		}
		fallthrough
	case noSynchronized:
		u.SynchronizeEngineBootsTime(rm.AuthEngineBoots, rm.AuthEngineTime)
		u.DiscoveryStatus = discovered
	case noDiscovered:
		u.AuthEngineId = rm.AuthEngineId
		if len(snmp.args.AuthPassword) > 0 {
			u.AuthKey = passwordToKey(
				snmp.args.AuthProtocol, snmp.args.AuthPassword, rm.AuthEngineId)
		}
		if len(snmp.args.PrivPassword) > 0 {
			u.PrivKey = passwordToKey(
				snmp.args.AuthProtocol, snmp.args.PrivPassword, rm.AuthEngineId)
		}
		u.DiscoveryStatus = noSynchronized
	}
	if err != nil {
		return
	}

	_, err = rm.Pdu().Unmarshal(rm.PduBytes())
	if err != nil {
		var note string
		if rm.Privacy() {
			note = " (probably Pdu was unable to decrypt)"
		}
		return ResponseError{
			Cause:   err,
			Message: fmt.Sprintf("Failed to Unmarshal Pdu%s", note),
			Detail:  fmt.Sprintf("Pdu Bytes - [%s]", toHexStr(rm.PduBytes(), " ")),
		}
	}
	p := rm.Pdu().(*ScopedPdu)

	if p.PduType() == GetResponse {
		var cxtId []byte
		if snmp.args.ContextEngineId != "" {
			cxtId, _ = engineIdToBytes(snmp.args.ContextEngineId)
		} else {
			cxtId = u.AuthEngineId
		}
		if !bytes.Equal(cxtId, p.ContextEngineId) {
			return ResponseError{
				Message: fmt.Sprintf("ContextEngineId mismatch - expected [%s], actual [%s]",
					toHexStr(cxtId, ""), toHexStr(p.ContextEngineId, "")),
			}
		}
		if name := snmp.args.ContextName; name != string(p.ContextName) {
			return ResponseError{
				Message: fmt.Sprintf("ContextName mismatch - expected [%s], actual [%s]",
					name, string(p.ContextName)),
			}
		}
		if sm.Authentication() && !rm.Authentication() {
			return ResponseError{
				Message: "Response message is not authenticated",
			}
		}
	}
	return
}

func (u *usm) Discover(snmp *SNMP) (err error) {
	if u.DiscoveryStatus == noDiscovered {
		// Send an empty Pdu with the NoAuthNoPriv
		orgSecLevel := snmp.args.SecurityLevel
		snmp.args.SecurityLevel = NoAuthNoPriv

		pdu := NewPdu(snmp.args.Version, GetRequest)
		_, err = snmp.sendPdu(pdu)

		snmp.args.SecurityLevel = orgSecLevel
		if err != nil {
			return
		}
	}

	if u.DiscoveryStatus == noSynchronized {
		// Send an empty Pdu
		pdu := NewPdu(snmp.args.Version, GetRequest)
		_, err = snmp.sendPdu(pdu)
		if err != nil {
			return
		}
	}

	return
}

func (u *usm) UpdateEngineBootsTime() error {
	now := time.Now()
	u.AuthEngineTime += int64(now.Sub(u.UpdatedTime).Seconds())
	if u.AuthEngineTime > math.MaxInt32 {
		u.AuthEngineBoots++
		// RFC3414 2.2.2
		if u.AuthEngineBoots == math.MaxInt32 {
			return fmt.Errorf("EngineBoots reached the max value, [%d]", math.MaxInt32)
		}
		u.AuthEngineTime -= math.MaxInt32
	}
	u.UpdatedTime = now
	return nil
}

func (u *usm) SynchronizeEngineBootsTime(engineBoots, engineTime int64) {
	u.AuthEngineBoots = engineBoots
	u.AuthEngineTime = engineTime
	u.UpdatedTime = time.Now()
}

func (u *usm) CheckTimeliness(engineBoots, engineTime int64) error {
	// RFC3414 Section 3.2 7) b)
	if engineBoots == math.MaxInt32 ||
		engineBoots < u.AuthEngineBoots ||
		(engineBoots == u.AuthEngineBoots && engineTime-u.AuthEngineTime > 150) {
		return ResponseError{
			Message: fmt.Sprintf(
				"The message is not in the time window - local [%d/%d], remote [%d/%d]",
				engineBoots, engineTime, u.AuthEngineBoots, u.AuthEngineTime),
		}
	}
	return nil
}

func (u *usm) String() string {
	return fmt.Sprintf(
		`{"DiscoveryStatus": "%s", "AuthEngineId": "%s", "AuthEngineBoots": "%d", `+
			`"AuthEngineTime": "%d", "AuthKey": "%s", "PrivKey": "%s", "UpdatedTime": "%s"}`,
		u.DiscoveryStatus, toHexStr(u.AuthEngineId, ""), u.AuthEngineBoots, u.AuthEngineTime,
		toHexStr(u.AuthKey, ""), toHexStr(u.PrivKey, ""), u.UpdatedTime)
}

func mac(msg *messageV3, proto AuthProtocol, key []byte) ([]byte, error) {
	tmp := msg.AuthParameter
	msg.AuthParameter = padding([]byte{}, 12)
	msgBytes, err := msg.Marshal()
	msg.AuthParameter = tmp
	if err != nil {
		return nil, err
	}

	var h hash.Hash
	switch proto {
	case Md5:
		h = hmac.New(md5.New, key)
	case Sha:
		h = hmac.New(sha1.New, key)
	}
	h.Write(msgBytes)
	return h.Sum(nil)[:12], nil
}

func encrypt(msg *messageV3, proto PrivProtocol, key []byte) (err error) {
	var dst, priv []byte
	src := msg.PduBytes()

	switch proto {
	case Des:
		dst, priv, err = encryptDES(src, key, int32(msg.AuthEngineBoots), genSalt32())
	case Aes:
		dst, priv, err = encryptAES(
			src, key, int32(msg.AuthEngineBoots), int32(msg.AuthEngineTime), genSalt64())
	}
	if err != nil {
		return
	}

	raw := asn1.RawValue{Class: classUniversal, Tag: tagOctetString, IsCompound: false}
	raw.Bytes = dst
	dst, err = asn1.Marshal(raw)
	if err == nil {
		msg.SetPduBytes(dst)
		msg.PrivParameter = priv
	}
	return
}

func decrypt(msg *messageV3, proto PrivProtocol, key, privParam []byte) (err error) {
	var raw asn1.RawValue
	_, err = asn1.Unmarshal(msg.PduBytes(), &raw)
	if err != nil {
		return
	}
	if raw.Class != classUniversal || raw.Tag != tagOctetString || raw.IsCompound {
		return asn1.StructuralError{fmt.Sprintf(
			"Invalid encryptedaPdu  object - Class [%02x], Tag [%02x] : [%s]",
			raw.Class, raw.Tag, toHexStr(msg.PduBytes(), " "))}
	}

	var dst []byte
	switch proto {
	case Des:
		dst, err = decryptDES(raw.Bytes, key, privParam)
	case Aes:
		dst, err = decryptAES(
			raw.Bytes, key, privParam, int32(msg.AuthEngineBoots), int32(msg.AuthEngineTime))
	}

	if err == nil {
		msg.SetPduBytes(dst)
	}
	return
}

func encryptDES(src, key []byte, engineBoots, salt int32) (dst, privParam []byte, err error) {

	block, err := des.NewCipher(key[:8])
	if err != nil {
		return
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, engineBoots)
	binary.Write(&buf, binary.BigEndian, salt)
	privParam = buf.Bytes()
	iv := xor(key[8:16], privParam)

	src = padding(src, des.BlockSize)
	dst = make([]byte, len(src))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(dst, src)
	return
}

func decryptDES(src, key, privParam []byte) (dst []byte, err error) {

	if len(src)%des.BlockSize != 0 {
		err = ArgumentError{
			Value:   len(src),
			Message: "Invalid DES cipher length",
		}
		return
	}
	if len(privParam) != 8 {
		err = ArgumentError{
			Value:   len(privParam),
			Message: "Invalid DES PrivParameter length",
		}
		return
	}

	block, err := des.NewCipher(key[:8])
	if err != nil {
		return
	}

	iv := xor(key[8:16], privParam)
	dst = make([]byte, len(src))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, src)
	return
}

func encryptAES(src, key []byte, engineBoots, engineTime int32, salt int64) (
	dst, privParam []byte, err error) {

	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return
	}

	var buf1, buf2 bytes.Buffer
	binary.Write(&buf1, binary.BigEndian, salt)
	privParam = buf1.Bytes()

	binary.Write(&buf2, binary.BigEndian, engineBoots)
	binary.Write(&buf2, binary.BigEndian, engineTime)
	iv := append(buf2.Bytes(), privParam...)

	src = padding(src, aes.BlockSize)
	dst = make([]byte, len(src))

	mode := cipher.NewCFBEncrypter(block, iv)
	mode.XORKeyStream(dst, src)
	return
}

func decryptAES(src, key, privParam []byte, engineBoots, engineTime int32) (
	dst []byte, err error) {

	if len(privParam) != 8 {
		err = ArgumentError{
			Value:   len(privParam),
			Message: "Invalid AES PrivParameter length",
		}
		return
	}

	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, engineBoots)
	binary.Write(&buf, binary.BigEndian, engineTime)
	iv := append(buf.Bytes(), privParam...)

	dst = make([]byte, len(src))

	mode := cipher.NewCFBDecrypter(block, iv)
	mode.XORKeyStream(dst, src)
	return
}

func passwordToKey(proto AuthProtocol, password string, engineId []byte) []byte {
	var h hash.Hash
	switch proto {
	case Md5:
		h = md5.New()
	case Sha:
		h = sha1.New()
	}

	pass := []byte(password)
	plen := len(pass)
	for i := mega / plen; i > 0; i-- {
		h.Write(pass)
	}
	remain := mega % plen
	if remain > 0 {
		h.Write(pass[:remain])
	}
	ku := h.Sum(nil)

	h.Reset()
	h.Write(ku)
	h.Write(engineId)
	h.Write(ku)
	return h.Sum(nil)
}
