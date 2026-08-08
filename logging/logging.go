// Package logging provides azwaf's logger. azwaf writes all diagnostics to
// its own slog logger instance — never to the process-global default logger —
// so applications embedding azwaf as a library get silence by default and
// full control when they want output.
//
// Defaults: WARN level, text handler on stderr. The azwaf CLI raises the
// level via the AZWAF_LOG environment variable; library consumers can call
// SetLevel/SetOutput, or replace the logger entirely with SetLogger.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// LevelTrace is azwaf's trace level, one step more verbose than slog's Debug.
const LevelTrace = slog.Level(slog.LevelDebug - 4)

var (
	mu sync.RWMutex

	// levelVar controls the level of the built-in handler. It has no effect
	// on loggers installed via SetLogger, which bring their own handlers.
	levelVar = func() *slog.LevelVar {
		lv := &slog.LevelVar{}
		lv.Set(slog.LevelWarn)

		return lv
	}()

	logger = slog.New(newTextHandler(os.Stderr))
)

func newTextHandler(w io.Writer) slog.Handler {
	return slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: levelVar,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// label the custom trace level as TRACE rather than DEBUG-4
			if a.Key == slog.LevelKey {
				if lvl, ok := a.Value.Any().(slog.Level); ok && lvl == LevelTrace {
					a.Value = slog.StringValue("TRACE")
				}
			}

			return a
		},
	})
}

// Logger returns the logger azwaf currently writes to.
func Logger() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()

	return logger
}

// SetLogger replaces azwaf's logger with one supplied by the application.
// Level filtering then belongs to the provided logger's handler: SetLevel
// only affects azwaf's built-in handler.
func SetLogger(l *slog.Logger) {
	if l == nil {
		return
	}

	mu.Lock()
	defer mu.Unlock()
	logger = l
}

// SetOutput points azwaf's built-in handler at w, keeping level control.
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	logger = slog.New(newTextHandler(w))
}

// SetLevel sets the minimum level emitted by azwaf's built-in handler.
func SetLevel(l slog.Level) {
	levelVar.Set(l)
}

// Level returns the built-in handler's current minimum level.
func Level() slog.Level {
	return levelVar.Level()
}

// Enabled reports whether a record at the given level would be emitted.
func Enabled(l slog.Level) bool {
	return Logger().Enabled(context.Background(), l)
}

// ParseLevel converts a textual level ("trace", "debug", "info", "warn",
// "warning", "error") into a slog.Level.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level: %q", s)
	}
}

func logf(level slog.Level, format string, args ...any) {
	l := Logger()
	if !l.Enabled(context.Background(), level) {
		return
	}

	l.Log(context.Background(), level, fmt.Sprintf(format, args...))
}

func logln(level slog.Level, args ...any) {
	l := Logger()
	if !l.Enabled(context.Background(), level) {
		return
	}

	l.Log(context.Background(), level, fmt.Sprint(args...))
}

// Tracef logs a formatted message at trace level.
func Tracef(format string, args ...any) { logf(LevelTrace, format, args...) }

// Debugf logs a formatted message at debug level.
func Debugf(format string, args ...any) { logf(slog.LevelDebug, format, args...) }

// Infof logs a formatted message at info level.
func Infof(format string, args ...any) { logf(slog.LevelInfo, format, args...) }

// Warnf logs a formatted message at warn level.
func Warnf(format string, args ...any) { logf(slog.LevelWarn, format, args...) }

// Errorf logs a formatted message at error level.
func Errorf(format string, args ...any) { logf(slog.LevelError, format, args...) }

// Trace logs a message at trace level.
func Trace(args ...any) { logln(LevelTrace, args...) }

// Debug logs a message at debug level.
func Debug(args ...any) { logln(slog.LevelDebug, args...) }

// Info logs a message at info level.
func Info(args ...any) { logln(slog.LevelInfo, args...) }

// Warn logs a message at warn level.
func Warn(args ...any) { logln(slog.LevelWarn, args...) }

// Error logs a message at error level.
func Error(args ...any) { logln(slog.LevelError, args...) }
