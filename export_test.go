package snmpgo

var StripHexPrefix = stripHexPrefix
var ToHexStr = toHexStr

// For snmpgo testing
func ArgsValidate(args *SNMPArguments) error { return args.validate() }
func SnmpCheckPdu(snmp *SNMP, pdu Pdu) error { return snmp.checkPdu(pdu) }

// For message testing
var NewMessage = newMessage
var NewMessageProcessing = newMessageProcessing

func ToMessageV1(msg message) *messageV1 { return msg.(*messageV1) }
func ToMessageV3(msg message) *messageV3 { return msg.(*messageV3) }
func ToUsm(sec security) *usm            { return sec.(*usm) }

// For security testing
var PasswordToKey = passwordToKey
var EncryptDES = encryptDES
var EncryptAES = encryptAES
var DecryptDES = decryptDES
var DecryptAES = decryptAES

func NewCommunity() *community { return &community{} }
func NewUsm() *usm             { return &usm{} }
