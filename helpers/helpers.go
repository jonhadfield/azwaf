package helpers

import (
	"runtime"
	"strings"
)

// GetFunctionName returns the name of the calling function.
func GetFunctionName() string {
	pc, _, _, _ := runtime.Caller(1) //nolint:dogsled

	complete := runtime.FuncForPC(pc).Name()
	split := strings.Split(complete, "/")

	return split[len(split)-1]
}
