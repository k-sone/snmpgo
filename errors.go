package snmpgo

import (
	"errors"
	"fmt"
)

var UnsupportedOperation error = errors.New("Unsupported operation")

// An ArgumentError suggests that the arguments are wrong
type ArgumentError struct {
	Value   interface{} // Argument that has a problem
	Message string      // Error message
}

func (e ArgumentError) Error() string {
	return fmt.Sprintf("%s, value `%v`", e.Message, e.Value)
}

// A ResponseError suggests that the response from the remote agent is wrong or is not obtained
type ResponseError struct {
	Cause   error  // Cause of the error
	Message string // Error message
	Detail  string // Detail of the error for debugging
}

func (e ResponseError) Error() string {
	if e.Cause == nil {
		return e.Message
	} else {
		return fmt.Sprintf("%s, cause `%v`", e.Message, e.Cause)
	}
}

type notInTimeWindowError struct {
	ResponseError
}
