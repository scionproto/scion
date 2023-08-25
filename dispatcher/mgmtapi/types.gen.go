// Package mgmtapi provides primitives to interact with the openapi HTTP API.
//
// Code generated by unknown module path version unknown version DO NOT EDIT.
package mgmtapi

// Defines values for LogLevelLevel.
const (
	Debug LogLevelLevel = "debug"
	Error LogLevelLevel = "error"
	Info  LogLevelLevel = "info"
)

// LogLevel defines model for LogLevel.
type LogLevel struct {
	// Level Logging level
	Level LogLevelLevel `json:"level"`
}

// LogLevelLevel Logging level
type LogLevelLevel string

// StandardError defines model for StandardError.
type StandardError struct {
	// Error Error message
	Error string `json:"error"`
}

// BadRequest defines model for BadRequest.
type BadRequest = StandardError

// SetLogLevelJSONRequestBody defines body for SetLogLevel for application/json ContentType.
type SetLogLevelJSONRequestBody = LogLevel
