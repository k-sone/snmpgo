package snmpgo

import (
	"fmt"
)

type SNMPError struct{}

type ArgumentError struct {
	Value   interface{}
	Message string
	SNMPError
}

func (e ArgumentError) Error() string {
	return fmt.Sprintf("%s, value `%v`", e.Message, e.Value)
}

type ResponseError struct {
	Cause   error
	Message string
	Detail  string
	SNMPError
}

func (e ResponseError) Error() string {
	if e.Cause == nil {
		return e.Message
	} else {
		return fmt.Sprintf("%s, cause `%v`", e.Message, e.Cause)
	}
}
