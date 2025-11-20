package helpers

import (
	"runtime"
	"strings"
)

// callerName returns the name of the function "skip" levels up the call stack.
func callerName(skip int) string {
	pc, _, _, _ := runtime.Caller(skip)
	complete := runtime.FuncForPC(pc).Name()
	split := strings.Split(complete, "/")
	return split[len(split)-1]
}

// GetFunctionName returns the name of the calling function.
func GetFunctionName() string {
	pc, _, _, _ := runtime.Caller(1) //nolint:dogsled

	complete := runtime.FuncForPC(pc).Name()
	split := strings.Split(complete, "/")

	return split[len(split)-1]
}

// GetParentFunctionName returns the name of the parent of the calling function.
func GetParentFunctionName() string { return callerName(3) }
