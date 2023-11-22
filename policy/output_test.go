package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrimString(t *testing.T) {
	// return input if same as max length
	require.Equal(t, "hello", TrimString("hello", 5, "..."))
	// return input if less than max length
	require.Equal(t, "hello", TrimString("hello", 6, "..."))
	// input shortened to three chars should be two chars of hello+"a"
	require.Equal(t, "hea", TrimString("hello", 3, "a"))
	// input shortened to four chars with suffix ... should return h...
	require.Equal(t, "h...", TrimString("hello", 4, "..."))
	// input shorted to four chars with suffix .... should return hell
	require.Equal(t, "hell", TrimString("hello", 4, "...."))
}
