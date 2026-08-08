package policy

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfirm(t *testing.T) {
	t.Cleanup(func() { confirmInput = os.Stdin })

	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "y accepts", input: "y\n", want: true},
		{name: "yes accepts", input: "yes\n", want: true},
		{name: "uppercase Y accepts", input: "Y\n", want: true},
		{name: "n declines", input: "n\n", want: false},
		{name: "anything else declines", input: "wat\n", want: false},
		{name: "empty input declines", input: "\n", want: false},
		{name: "eof declines", input: "", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			confirmInput = strings.NewReader(tc.input)
			require.Equal(t, tc.want, Confirm("item", "request"))
		})
	}
}
