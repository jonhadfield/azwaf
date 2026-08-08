package logging

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// resetAfter restores the package logger and level once the test completes.
func resetAfter(t *testing.T) {
	t.Helper()

	prevLevel := Level()

	t.Cleanup(func() {
		SetLevel(prevLevel)
		SetOutput(os.Stderr)
	})
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in      string
		want    slog.Level
		wantErr bool
	}{
		{in: "trace", want: LevelTrace},
		{in: "debug", want: slog.LevelDebug},
		{in: "info", want: slog.LevelInfo},
		{in: "warn", want: slog.LevelWarn},
		{in: "warning", want: slog.LevelWarn},
		{in: "error", want: slog.LevelError},
		{in: " Debug ", want: slog.LevelDebug},
		{in: "nonsense", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseLevel(tc.in)

			if tc.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestDefaultLevelFiltersBelowWarn(t *testing.T) {
	resetAfter(t)

	var buf bytes.Buffer

	SetOutput(&buf)
	SetLevel(slog.LevelWarn)

	Tracef("trace %d", 1)
	Debugf("debug %d", 1)
	Infof("info %d", 1)
	require.Zero(t, buf.Len(), "below-warn output must be suppressed")

	Warnf("warn %d", 1)
	Errorf("error %d", 1)
	out := buf.String()
	require.Contains(t, out, "warn 1")
	require.Contains(t, out, "error 1")
}

func TestTraceLevelAndLabel(t *testing.T) {
	resetAfter(t)

	var buf bytes.Buffer

	SetOutput(&buf)
	SetLevel(LevelTrace)

	Tracef("tracing %s", "here")
	require.Contains(t, buf.String(), "level=TRACE")
	require.Contains(t, buf.String(), "tracing here")

	require.True(t, Enabled(LevelTrace))
	require.True(t, Enabled(slog.LevelDebug))
}

func TestNonFormattingVariants(t *testing.T) {
	resetAfter(t)

	var buf bytes.Buffer

	SetOutput(&buf)
	SetLevel(slog.LevelDebug)

	Debug("plain debug")
	Info("plain info")
	Warn("plain warn")
	Error("plain error")

	out := buf.String()
	for _, want := range []string{"plain debug", "plain info", "plain warn", "plain error"} {
		require.Contains(t, out, want)
	}
}

func TestSetLoggerReplacesDestination(t *testing.T) {
	resetAfter(t)

	var builtin, custom bytes.Buffer

	SetOutput(&builtin)

	SetLogger(slog.New(slog.NewTextHandler(&custom, &slog.HandlerOptions{Level: slog.LevelInfo})))

	Infof("to custom")
	require.Zero(t, builtin.Len())
	require.Contains(t, custom.String(), "to custom")

	// nil is ignored rather than breaking the logger
	SetLogger(nil)
	Infof("still custom")
	require.True(t, strings.Contains(custom.String(), "still custom"))
}
