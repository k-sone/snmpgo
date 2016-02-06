package snmpgo

var StripHexPrefix = stripHexPrefix
var ToHexStr = toHexStr
var Retry = retry
var NewNotInTimeWindowError = func() error { return &notInTimeWindowError{&MessageError{}} }

// For snmpgo testing
var NewSNMPEngine = newSNMPEngine

func ArgsValidate(args *SNMPArguments) error { return args.validate() }
func CheckPdu(engine *snmpEngine, pdu Pdu, args *SNMPArguments) error {
	return engine.checkPdu(pdu, args)
}

// For message testing
var NewMessage = newMessage
var UnmarshalMessage = unmarshalMessage
var NewMessageWithPdu = newMessageWithPdu
var NewMessageProcessing = newMessageProcessing

func ToMessageV1(msg message) *messageV1 { return msg.(*messageV1) }
func ToMessageV3(msg message) *messageV3 { return msg.(*messageV3) }
func ToUsm(sec security) *usm            { return sec.(*usm) }

// For security testing
var NewSecurity = newSecurity
var PasswordToKey = passwordToKey
var EncryptDES = encryptDES
var EncryptAES = encryptAES
var DecryptDES = decryptDES
var DecryptAES = decryptAES

func NewCommunity() *community { return &community{} }
func NewUsm() *usm             { return &usm{} }
