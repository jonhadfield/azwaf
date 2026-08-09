package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBackupPoliciesInputValidate(t *testing.T) {
	cases := []struct {
		name       string
		input      BackupPoliciesInput
		wantErrStr string
	}{
		{
			name:       "no subscription and no resource ids errors",
			input:      BackupPoliciesInput{},
			wantErrStr: "subscription-id required",
		},
		{
			name: "resource ids without subscription is allowed",
			input: BackupPoliciesInput{
				RIDs: []string{"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/p1"},
			},
		},
		{
			name: "valid subscription id is allowed",
			input: BackupPoliciesInput{
				BaseCLIInput: BaseCLIInput{SubscriptionID: "00000000-0000-0000-0000-000000000000"},
			},
		},
		{
			name: "malformed subscription id errors",
			input: BackupPoliciesInput{
				BaseCLIInput: BaseCLIInput{SubscriptionID: "not-a-uuid"},
			},
			wantErrStr: "subscription",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.Validate()

			if tc.wantErrStr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErrStr)

				return
			}

			require.NoError(t, err)
		})
	}
}
