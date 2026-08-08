package policy

// Regression tests for azwaf-as-a-library logging behavior: with default
// settings azwaf must produce NO log output, and raising the level must be
// scoped to azwaf's own logger — the process-global slog default logger is
// never touched.

import (
	"bytes"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jonhadfield/azwaf/internal/azfakes"
	"github.com/jonhadfield/azwaf/logging"
)

func TestLibraryIsSilentByDefault(t *testing.T) {
	t.Cleanup(func() {
		logging.SetLevel(slog.LevelWarn)
		logging.SetOutput(os.Stderr)
	})

	var buf bytes.Buffer

	logging.SetOutput(&buf)
	logging.SetLevel(slog.LevelWarn) // the library default

	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())
	st.AddAppGWPolicy("rg-one", "agw-one", newAppGWPolicyForTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	// exercise chatty paths: list/fetch both WAF types and push a change
	_, err = GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{SubscriptionID: azfakesSubID})
	require.NoError(t, err)

	_, err = GetWrappedAppGWPoliciesFromRawIDs(s, GetWrappedPoliciesInput{SubscriptionID: azfakesSubID})
	require.NoError(t, err)

	require.NoError(t, ProcessAppGWPolicyChanges(&ProcessAppGWPolicyChangesInput{
		Session:          s,
		PolicyName:       "agw-one",
		SubscriptionID:   azfakesSubID,
		ResourceGroup:    "rg-one",
		PolicyPostChange: newAppGWPolicyForTest(),
	}))

	require.Zero(t, buf.Len(), "azwaf must be silent at its default level, got: %s", buf.String())

	// opting in to debug produces output on azwaf's logger
	logging.SetLevel(slog.LevelDebug)

	_, err = GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{SubscriptionID: azfakesSubID})
	require.NoError(t, err)
	require.NotZero(t, buf.Len(), "debug level must produce output")
}

func TestLibraryNeverTouchesGlobalSlogDefault(t *testing.T) {
	t.Cleanup(func() {
		logging.SetLevel(slog.LevelWarn)
		logging.SetOutput(os.Stderr)
	})

	before := slog.Default()

	logging.SetOutput(&bytes.Buffer{})
	logging.SetLevel(slog.LevelDebug)

	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	_, err = GetWrappedPoliciesFromRawIDs(s, GetWrappedPoliciesInput{SubscriptionID: azfakesSubID})
	require.NoError(t, err)

	// the application's global logger must be exactly as it was
	require.Same(t, before, slog.Default())
}
