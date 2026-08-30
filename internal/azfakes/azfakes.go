// Package azfakes provides an in-memory implementation of the Azure WAF
// endpoints used by azwaf, built on the official Azure SDK fake servers.
// Tests receive a fully wired *session.Session whose clients speak to an
// in-memory Store over the SDK's fake transport — no network calls and no
// real credentials are ever involved, while the SDK's genuine serialization,
// paging, and long-running-operation code still runs.
//
// Blob storage is intentionally out of scope: pass a nil blob client to the
// backup functions and use disk paths instead.
package azfakes

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	fdfake "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	netfake "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8/fake"
	"github.com/tidwall/buntdb"

	"github.com/jonhadfield/azwaf/session"
)

// resource type segments used to construct policy resource ids. These
// intentionally duplicate the constants in the policy package: importing it
// here would create an import cycle for the policy package's own tests.
const (
	frontDoorWAFType = "frontdoorWebApplicationFirewallPolicies"
	appGWWAFType     = "ApplicationGatewayWebApplicationFirewallPolicies"
)

// FrontDoorPolicyID returns the resource id for a Front Door WAF policy.
func FrontDoorPolicyID(subscriptionID, resourceGroup, name string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/%s/%s",
		subscriptionID, resourceGroup, frontDoorWAFType, name)
}

// AppGWPolicyID returns the resource id for an Application Gateway WAF policy.
func AppGWPolicyID(subscriptionID, resourceGroup, name string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/%s/%s",
		subscriptionID, resourceGroup, appGWWAFType, name)
}

// PushedFrontDoorPolicy records a single Front Door CreateOrUpdate call.
type PushedFrontDoorPolicy struct {
	ResourceGroup string
	Name          string
	Policy        armfrontdoor.WebApplicationFirewallPolicy
}

// PushedAppGWPolicy records a single AppGW CreateOrUpdate call.
type PushedAppGWPolicy struct {
	ResourceGroup string
	Name          string
	Policy        armnetwork.WebApplicationFirewallPolicy
}

// Store holds the in-memory Azure state served by the fake endpoints. Seed it
// with Add* before calling NewSession; inspect Pushed* afterwards to assert
// exactly what would have been written to Azure.
type Store struct {
	SubscriptionID string

	mu              sync.Mutex
	frontDoor       map[string]*armfrontdoor.WebApplicationFirewallPolicy
	appGW           map[string]*armnetwork.WebApplicationFirewallPolicy
	pushedFrontDoor []PushedFrontDoorPolicy
	pushedAppGW     []PushedAppGWPolicy
}

// NewStore returns an empty Store for the given subscription.
func NewStore(subscriptionID string) *Store {
	return &Store{
		SubscriptionID: subscriptionID,
		frontDoor:      make(map[string]*armfrontdoor.WebApplicationFirewallPolicy),
		appGW:          make(map[string]*armnetwork.WebApplicationFirewallPolicy),
	}
}

// storeKey matches Azure's case-insensitive treatment of resource identifiers.
func storeKey(resourceGroup, name string) string {
	return strings.ToLower(resourceGroup + "/" + name)
}

// AddFrontDoorPolicy seeds a Front Door WAF policy, stamping its ID and Name
// from the components. The policy's resource id is returned.
func (st *Store) AddFrontDoorPolicy(resourceGroup, name string, p armfrontdoor.WebApplicationFirewallPolicy) string {
	id := FrontDoorPolicyID(st.SubscriptionID, resourceGroup, name)
	p.ID = &id
	n := name
	p.Name = &n

	st.mu.Lock()
	defer st.mu.Unlock()
	st.frontDoor[storeKey(resourceGroup, name)] = &p

	return id
}

// AddAppGWPolicy seeds an Application Gateway WAF policy, stamping its ID and
// Name from the components. The policy's resource id is returned.
func (st *Store) AddAppGWPolicy(resourceGroup, name string, p armnetwork.WebApplicationFirewallPolicy) string {
	id := AppGWPolicyID(st.SubscriptionID, resourceGroup, name)
	p.ID = &id
	n := name
	p.Name = &n

	st.mu.Lock()
	defer st.mu.Unlock()
	st.appGW[storeKey(resourceGroup, name)] = &p

	return id
}

// FrontDoorPolicy returns the stored Front Door policy, if present.
func (st *Store) FrontDoorPolicy(resourceGroup, name string) (armfrontdoor.WebApplicationFirewallPolicy, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()

	p, ok := st.frontDoor[storeKey(resourceGroup, name)]
	if !ok {
		return armfrontdoor.WebApplicationFirewallPolicy{}, false
	}

	return *p, true
}

// AppGWPolicy returns the stored AppGW policy, if present.
func (st *Store) AppGWPolicy(resourceGroup, name string) (armnetwork.WebApplicationFirewallPolicy, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()

	p, ok := st.appGW[storeKey(resourceGroup, name)]
	if !ok {
		return armnetwork.WebApplicationFirewallPolicy{}, false
	}

	return *p, true
}

// PushedFrontDoor returns a copy of every recorded Front Door CreateOrUpdate.
func (st *Store) PushedFrontDoor() []PushedFrontDoorPolicy {
	st.mu.Lock()
	defer st.mu.Unlock()

	out := make([]PushedFrontDoorPolicy, len(st.pushedFrontDoor))
	copy(out, st.pushedFrontDoor)

	return out
}

// PushedAppGW returns a copy of every recorded AppGW CreateOrUpdate.
func (st *Store) PushedAppGW() []PushedAppGWPolicy {
	st.mu.Lock()
	defer st.mu.Unlock()

	out := make([]PushedAppGWPolicy, len(st.pushedAppGW))
	copy(out, st.pushedAppGW)

	return out
}

func (st *Store) upsertFrontDoor(resourceGroup, name string, p armfrontdoor.WebApplicationFirewallPolicy) armfrontdoor.WebApplicationFirewallPolicy {
	id := FrontDoorPolicyID(st.SubscriptionID, resourceGroup, name)
	p.ID = &id
	n := name
	p.Name = &n

	st.mu.Lock()
	defer st.mu.Unlock()
	st.frontDoor[storeKey(resourceGroup, name)] = &p
	st.pushedFrontDoor = append(st.pushedFrontDoor, PushedFrontDoorPolicy{
		ResourceGroup: resourceGroup,
		Name:          name,
		Policy:        p,
	})

	return p
}

func (st *Store) upsertAppGW(resourceGroup, name string, p armnetwork.WebApplicationFirewallPolicy) armnetwork.WebApplicationFirewallPolicy {
	id := AppGWPolicyID(st.SubscriptionID, resourceGroup, name)
	p.ID = &id
	n := name
	p.Name = &n

	st.mu.Lock()
	defer st.mu.Unlock()
	st.appGW[storeKey(resourceGroup, name)] = &p
	st.pushedAppGW = append(st.pushedAppGW, PushedAppGWPolicy{
		ResourceGroup: resourceGroup,
		Name:          name,
		Policy:        p,
	})

	return p
}

func (st *Store) frontDoorPolicyList() []*armfrontdoor.WebApplicationFirewallPolicy {
	st.mu.Lock()
	defer st.mu.Unlock()

	out := make([]*armfrontdoor.WebApplicationFirewallPolicy, 0, len(st.frontDoor))
	for _, p := range st.frontDoor {
		out = append(out, p)
	}

	return out
}

func (st *Store) appGWPolicyList() []*armnetwork.WebApplicationFirewallPolicy {
	st.mu.Lock()
	defer st.mu.Unlock()

	out := make([]*armnetwork.WebApplicationFirewallPolicy, 0, len(st.appGW))
	for _, p := range st.appGW {
		out = append(out, p)
	}

	return out
}

// frontDoorPoliciesServer implements the Front Door WAF policies endpoints:
// Get, list-by-subscription, and (LRO) CreateOrUpdate.
func (st *Store) frontDoorPoliciesServer() *fdfake.PoliciesServer {
	return &fdfake.PoliciesServer{
		Get: func(_ context.Context, resourceGroupName, policyName string, _ *armfrontdoor.PoliciesClientGetOptions) (resp azfake.Responder[armfrontdoor.PoliciesClientGetResponse], errResp azfake.ErrorResponder) {
			p, ok := st.FrontDoorPolicy(resourceGroupName, policyName)
			if !ok {
				errResp.SetResponseError(http.StatusNotFound, "ResourceNotFound")

				return
			}

			resp.SetResponse(http.StatusOK, armfrontdoor.PoliciesClientGetResponse{WebApplicationFirewallPolicy: p}, nil)

			return
		},
		NewListBySubscriptionPager: func(_ *armfrontdoor.PoliciesClientListBySubscriptionOptions) (resp azfake.PagerResponder[armfrontdoor.PoliciesClientListBySubscriptionResponse]) {
			resp.AddPage(http.StatusOK, armfrontdoor.PoliciesClientListBySubscriptionResponse{
				WebApplicationFirewallPolicyList: armfrontdoor.WebApplicationFirewallPolicyList{
					Value: st.frontDoorPolicyList(),
				},
			}, nil)

			return
		},
		BeginCreateOrUpdate: func(_ context.Context, resourceGroupName, policyName string, parameters armfrontdoor.WebApplicationFirewallPolicy, _ *armfrontdoor.PoliciesClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armfrontdoor.PoliciesClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
			stored := st.upsertFrontDoor(resourceGroupName, policyName, parameters)
			resp.SetTerminalResponse(http.StatusOK, armfrontdoor.PoliciesClientCreateOrUpdateResponse{WebApplicationFirewallPolicy: stored}, nil)

			return
		},
	}
}

func (st *Store) frontDoorsServer() *fdfake.FrontDoorsServer {
	return &fdfake.FrontDoorsServer{
		NewListPager: func(_ *armfrontdoor.FrontDoorsClientListOptions) (resp azfake.PagerResponder[armfrontdoor.FrontDoorsClientListResponse]) {
			// the store has no Front Doors to seed, so the list is always empty
			resp.AddPage(http.StatusOK, armfrontdoor.FrontDoorsClientListResponse{}, nil)

			return
		},
	}
}

func (st *Store) managedRuleSetsServer() *fdfake.ManagedRuleSetsServer {
	return &fdfake.ManagedRuleSetsServer{
		NewListPager: func(_ *armfrontdoor.ManagedRuleSetsClientListOptions) (resp azfake.PagerResponder[armfrontdoor.ManagedRuleSetsClientListResponse]) {
			// no rule set definitions to seed, so the list is always empty
			resp.AddPage(http.StatusOK, armfrontdoor.ManagedRuleSetsClientListResponse{}, nil)

			return
		},
	}
}

// appGWPoliciesServer implements the Application Gateway WAF policies
// endpoints: Get, list-all, and CreateOrUpdate.
func (st *Store) appGWPoliciesServer() *netfake.WebApplicationFirewallPoliciesServer {
	return &netfake.WebApplicationFirewallPoliciesServer{
		Get: func(_ context.Context, resourceGroupName, policyName string, _ *armnetwork.WebApplicationFirewallPoliciesClientGetOptions) (resp azfake.Responder[armnetwork.WebApplicationFirewallPoliciesClientGetResponse], errResp azfake.ErrorResponder) {
			p, ok := st.AppGWPolicy(resourceGroupName, policyName)
			if !ok {
				errResp.SetResponseError(http.StatusNotFound, "ResourceNotFound")

				return
			}

			resp.SetResponse(http.StatusOK, armnetwork.WebApplicationFirewallPoliciesClientGetResponse{WebApplicationFirewallPolicy: p}, nil)

			return
		},
		NewListAllPager: func(_ *armnetwork.WebApplicationFirewallPoliciesClientListAllOptions) (resp azfake.PagerResponder[armnetwork.WebApplicationFirewallPoliciesClientListAllResponse]) {
			resp.AddPage(http.StatusOK, armnetwork.WebApplicationFirewallPoliciesClientListAllResponse{
				WebApplicationFirewallPolicyListResult: armnetwork.WebApplicationFirewallPolicyListResult{
					Value: st.appGWPolicyList(),
				},
			}, nil)

			return
		},
		CreateOrUpdate: func(_ context.Context, resourceGroupName, policyName string, parameters armnetwork.WebApplicationFirewallPolicy, _ *armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateOptions) (resp azfake.Responder[armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
			stored := st.upsertAppGW(resourceGroupName, policyName, parameters)
			resp.SetResponse(http.StatusOK, armnetwork.WebApplicationFirewallPoliciesClientCreateOrUpdateResponse{WebApplicationFirewallPolicy: stored}, nil)

			return
		},
	}
}

// NewSession returns a *session.Session whose Azure clients are wired to this
// Store via the SDK fake transports. Because the session's client maps are
// pre-populated, azwaf's lazy client constructors return early and no
// credential acquisition is attempted.
//
// baseDir, when non-empty, roots the session's working/backup/cache paths so
// nothing touches ~/.azwaf; pass t.TempDir(). With an empty baseDir the cache
// is opened in memory and no directories are created.
func (st *Store) NewSession(baseDir string) (*session.Session, error) {
	cred := &azfake.TokenCredential{}

	clientOpts := func(tr azpolicy.Transporter) *arm.ClientOptions {
		return &arm.ClientOptions{ClientOptions: azpolicy.ClientOptions{Transport: tr}}
	}

	fdPolicies, err := armfrontdoor.NewPoliciesClient(st.SubscriptionID, cred,
		clientOpts(fdfake.NewPoliciesServerTransport(st.frontDoorPoliciesServer())))
	if err != nil {
		return nil, fmt.Errorf("azfakes - failed to create front door policies client: %w", err)
	}

	frontDoors, err := armfrontdoor.NewFrontDoorsClient(st.SubscriptionID, cred,
		clientOpts(fdfake.NewFrontDoorsServerTransport(st.frontDoorsServer())))
	if err != nil {
		return nil, fmt.Errorf("azfakes - failed to create front doors client: %w", err)
	}

	ruleSets, err := armfrontdoor.NewManagedRuleSetsClient(st.SubscriptionID, cred,
		clientOpts(fdfake.NewManagedRuleSetsServerTransport(st.managedRuleSetsServer())))
	if err != nil {
		return nil, fmt.Errorf("azfakes - failed to create managed rule sets client: %w", err)
	}

	appGWPolicies, err := armnetwork.NewWebApplicationFirewallPoliciesClient(st.SubscriptionID, cred,
		clientOpts(netfake.NewWebApplicationFirewallPoliciesServerTransport(st.appGWPoliciesServer())))
	if err != nil {
		return nil, fmt.Errorf("azfakes - failed to create appgw policies client: %w", err)
	}

	s := &session.Session{
		ClientCredential:                 cred,
		FrontDoorPoliciesClients:         map[string]*armfrontdoor.PoliciesClient{st.SubscriptionID: fdPolicies},
		FrontDoorsClients:                map[string]*armfrontdoor.FrontDoorsClient{st.SubscriptionID: frontDoors},
		FrontDoorsManagedRuleSetsClients: map[string]*armfrontdoor.ManagedRuleSetsClient{st.SubscriptionID: ruleSets},
		AppGWPoliciesClients:             map[string]*armnetwork.WebApplicationFirewallPoliciesClient{st.SubscriptionID: appGWPolicies},
	}

	cachePath := ":memory:"

	if baseDir != "" {
		backupsDir := filepath.Join(baseDir, "backups")
		if err := os.MkdirAll(backupsDir, 0o755); err != nil {
			return nil, fmt.Errorf("azfakes - failed to create backups dir: %w", err)
		}

		s.WorkingDir = baseDir
		s.BackupsDir = backupsDir
		s.CacheDir = baseDir
		cachePath = filepath.Join(baseDir, "cache.db")
	}

	db, err := buntdb.Open(cachePath)
	if err != nil {
		return nil, fmt.Errorf("azfakes - failed to open cache: %w", err)
	}

	s.CachePath = cachePath
	s.Cache = db

	return s, nil
}
