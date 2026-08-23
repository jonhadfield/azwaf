package session

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// InitialiseCache used to panic on a nil receiver, and with an unformatted
// format string at that — the literal "%s called with null session" reached the
// user. A library must not bring the host process down for this.
func TestInitialiseCacheOnNilSessionDoesNotPanic(t *testing.T) {
	var s *Session

	require.NotPanics(t, func() {
		s.InitialiseCache()
	})
}

// Guard the package the same way policy is guarded.
func TestNoPanicsInSessionPackage(t *testing.T) {
	var offenders []string

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}

		file, perr := parser.ParseFile(fset, e.Name(), nil, 0)
		require.NoError(t, perr)

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "panic" {
				offenders = append(offenders, fset.Position(call.Pos()).String())
			}

			return true
		})
	}

	require.Empty(t, offenders,
		"library code must return errors rather than panic; found panic at %v", offenders)
}
