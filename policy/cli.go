package policy

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// confirmInput is the source of interactive confirmation responses. It exists
// so tests can script answers; production always reads stdin.
var confirmInput io.Reader = os.Stdin

func Confirm(item, request string) bool {
	fmt.Println(item)
	fmt.Printf("%s [y|N]: ", request)

	var s string

	if _, err := fmt.Fscanln(confirmInput, &s); err != nil {
		return false
	}

	s = strings.TrimSpace(s)

	s = strings.ToLower(s)

	if s == "y" || s == "yes" {
		return true
	}

	return false
}
