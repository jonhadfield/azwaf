package session

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/stretchr/testify/require"
)

func testSession() *Session {
	return &Session{ClientCredential: &fake.TokenCredential{}}
}

const testSubID = "10000000-0000-0000-0000-000000000001"

// Each getter creates a client on first call and re-uses it after. This pins
// that, and the guards each one applies, before they were collapsed onto a
// shared implementation.
func TestClientGettersCacheAndGuard(t *testing.T) {
	t.Run("front door policies", func(t *testing.T) {
		s := testSession()
		require.NoError(t, s.GetFrontDoorPoliciesClient(testSubID))
		first := s.FrontDoorPoliciesClients[testSubID]
		require.NotNil(t, first)

		require.NoError(t, s.GetFrontDoorPoliciesClient(testSubID))
		require.Same(t, first, s.FrontDoorPoliciesClients[testSubID], "second call re-uses the client")
	})

	t.Run("appgw policies", func(t *testing.T) {
		s := testSession()
		require.NoError(t, s.GetAppGWPoliciesClient(testSubID))
		first := s.AppGWPoliciesClients[testSubID]
		require.NotNil(t, first)

		require.NoError(t, s.GetAppGWPoliciesClient(testSubID))
		require.Same(t, first, s.AppGWPoliciesClients[testSubID])
	})

	t.Run("managed rule sets", func(t *testing.T) {
		s := testSession()
		require.NoError(t, s.GetManagedRuleSetsClient(testSubID))
		first := s.FrontDoorsManagedRuleSetsClients[testSubID]
		require.NotNil(t, first)

		require.NoError(t, s.GetManagedRuleSetsClient(testSubID))
		require.Same(t, first, s.FrontDoorsManagedRuleSetsClients[testSubID])
	})

	t.Run("front doors", func(t *testing.T) {
		s := testSession()
		_, err := s.GetFrontDoorsClient(testSubID)
		require.NoError(t, err)
		require.NotNil(t, s.FrontDoorsClients[testSubID])

		_, err = s.GetFrontDoorsClient(testSubID)
		require.NoError(t, err)
	})
}

// An empty subscription id is rejected rather than used to build a client that
// could never work.
func TestClientGettersRejectEmptySubscriptionID(t *testing.T) {
	s := testSession()

	require.Error(t, s.GetFrontDoorPoliciesClient(""))
	require.Error(t, s.GetAppGWPoliciesClient(""))
	require.Error(t, s.GetManagedRuleSetsClient(""))

	_, err := s.GetFrontDoorsClient("")
	require.Error(t, err)
}

// A nil session is an error, not a panic.
func TestClientGettersRejectNilSession(t *testing.T) {
	var s *Session

	require.NotPanics(t, func() {
		require.Error(t, s.GetFrontDoorPoliciesClient(testSubID))
		require.Error(t, s.GetAppGWPoliciesClient(testSubID))
		require.Error(t, s.GetManagedRuleSetsClient(testSubID))

		_, err := s.GetFrontDoorsClient(testSubID)
		require.Error(t, err)
	})
}
