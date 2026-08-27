package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jonhadfield/azwaf/config"
	"github.com/jonhadfield/azwaf/logging"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/azwaf/session"
)

// GetFrontDoorByID returns a front door instance for the provided id.
// It includes endpoints with any associated waf Policies.
func GetFrontDoorByID(s *session.Session, frontDoorID string) (FrontDoor, error) {
	funcName := GetFunctionName()
	ctx := context.Background()

	rID := config.ParseResourceID(frontDoorID)

	c, err := s.GetFrontDoorsClient(rID.SubscriptionID)
	if err != nil {
		return FrontDoor{}, fmt.Errorf("%s - %w", funcName, err)
	}

	rawFrontDoor, merr := c.Get(ctx, rID.ResourceGroup, rID.Name, nil)
	if merr != nil {
		return FrontDoor{}, fmt.Errorf("%s - %s", funcName, merr.Error())
	}

	policies := make(map[string]armfrontdoor.WebApplicationFirewallPolicy)

	var frontDoorEndpoints []FrontDoorEndpoint

	for _, e := range rawFrontDoor.Properties.FrontendEndpoints {
		if e.Properties.WebApplicationFirewallPolicyLink != nil && e.Properties.WebApplicationFirewallPolicyLink.ID != nil {
			var wafPolicy *armfrontdoor.WebApplicationFirewallPolicy

			val, ok := policies[*e.Properties.WebApplicationFirewallPolicyLink.ID]

			if !ok {
				rid := config.ParseResourceID(*e.Properties.WebApplicationFirewallPolicyLink.ID)

				wafPolicy, err = GetRawPolicy(s, rID.SubscriptionID, rid.ResourceGroup, rid.Name)
				if err != nil {
					return FrontDoor{}, fmt.Errorf("%s - %w", funcName, err)
				}

				policies[*e.Properties.WebApplicationFirewallPolicyLink.ID] = *wafPolicy
			} else {
				wafPolicy = &val
			}

			frontDoorEndpoints = append(frontDoorEndpoints, FrontDoorEndpoint{
				name:      *e.Name,
				hostName:  *e.Properties.HostName,
				wafPolicy: *wafPolicy,
			})
		}
	}

	return FrontDoor{
		name:      *rawFrontDoor.Name,
		endpoints: frontDoorEndpoints,
	}, nil
}

// PushPolicyInput defines the input for the pushPolicy function
type PushPolicyInput struct {
	Name          string
	Subscription  string
	ResourceGroup string
	Policy        armfrontdoor.WebApplicationFirewallPolicy
	Debug         bool
	Timeout       int64
	Async         bool
}

const (
	PushPolicyTimeout       = 120
	PushPolicyPollFrequency = 20
)

// PushPolicy creates or updates a waf Policy with the provided Policy instance.
func PushPolicy(s *session.Session, i *PushPolicyInput) error {
	funcName := GetFunctionName()

	logging.Debugf("pushing policy %s...", i.Name)

	// backstop for callers that reach PushPolicy without going through
	// ProcessPolicyChanges, so no path can push an over-limit policy
	if err := validatePolicyLimits(&i.Policy); err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	ctx := context.Background()

	// check we're not missing a policies client for the Subscription
	err := s.GetFrontDoorPoliciesClient(i.Subscription)
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	poller, err := s.FrontDoorPoliciesClients[i.Subscription].BeginCreateOrUpdate(ctx, i.ResourceGroup, i.Name, i.Policy, nil)
	if err != nil {
		return fmt.Errorf("%s - %w", funcName, err)
	}

	if i.Async {
		logging.Info("asynchronous policy push started")

		return nil
	}

	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s - failed to poll create/update result: %w", funcName, err)
	}

	logging.Infof("policy %s updated", *i.Policy.Name)

	return nil
}

type GetWrappedPoliciesInput struct {
	SubscriptionID    string
	AppVersion        string
	Config            string
	FilterResourceIDs []string
	Max               int
}

type GetWrappedPoliciesOutput struct {
	Policies []WrappedPolicy
}

type FrontDoorEndpoint struct {
	name      string
	hostName  string
	wafPolicy armfrontdoor.WebApplicationFirewallPolicy
}

type FrontDoor struct {
	name      string
	endpoints []FrontDoorEndpoint
}

type FrontDoors []FrontDoor

func LoadPolicyFromFile(f string) (armfrontdoor.WebApplicationFirewallPolicy, error) {
	funcName := GetFunctionName()

	// #nosec
	data, err := os.ReadFile(f)
	if err != nil {
		return armfrontdoor.WebApplicationFirewallPolicy{},
			fmt.Errorf("%s - failed to read file %s: %w", funcName, f, err)
	}

	var p armfrontdoor.WebApplicationFirewallPolicy
	if err = json.Unmarshal(data, &p); err != nil {
		return armfrontdoor.WebApplicationFirewallPolicy{},
			fmt.Errorf("%s - failed to unmarshal policy: %w", funcName, err)
	}

	return p, nil
}

func LoadWrappedPolicyFromFile(f string) (WrappedPolicy, error) {
	funcName := GetFunctionName()
	logging.Debugf("%s | loading file %s", funcName, f)
	// #nosec
	data, err := os.ReadFile(f)
	if err != nil {
		return WrappedPolicy{}, fmt.Errorf("%s - %w", funcName, err)
	}

	logging.Debugf("%s | loaded %d bytes of data from %s", funcName, len(data), f)

	var wp WrappedPolicy

	err = json.Unmarshal(data, &wp)
	if err != nil {
		return WrappedPolicy{}, fmt.Errorf("%s - %w", funcName, err)
	}

	if wp.Policy.Properties == nil {
		return WrappedPolicy{}, fmt.Errorf("%s - wrapped policy is invalid", funcName)
	}

	return wp, nil
}

// LoadedBackups separates loaded backup files by WAF type.
type LoadedBackups struct {
	FrontDoor []WrappedPolicy
	AppGW     []WrappedAppGWPolicy
}

// wafTypePeek is used to identify the WAF type of a backup file before fully
// unmarshaling it into the correct concrete type.
type wafTypePeek struct {
	WAFType string `json:"WAFType"`
}

// LoadAllBackupsFromPaths walks each path (file or directory) and loads every
// JSON backup it finds, dispatching each file to either the FrontDoor or AppGW
// type based on the WAFType field embedded in the backup. Backups produced by
// older versions of azwaf have no WAFType and are treated as FrontDoor.
func LoadAllBackupsFromPaths(paths []string) (LoadedBackups, error) {
	funcName := GetFunctionName()

	if len(paths) == 0 {
		return LoadedBackups{}, fmt.Errorf("%s - no paths provided", funcName)
	}

	var out LoadedBackups

	for _, p := range paths {
		got, err := loadAllBackupsFromPath(p)
		if err != nil {
			return LoadedBackups{}, fmt.Errorf("%s - %w", funcName, err)
		}

		out.FrontDoor = append(out.FrontDoor, got.FrontDoor...)
		out.AppGW = append(out.AppGW, got.AppGW...)
	}

	logging.Debugf("loaded %d FrontDoor and %d AppGW policy backups", len(out.FrontDoor), len(out.AppGW))

	return out, nil
}

func loadAllBackupsFromPath(rootPath string) (LoadedBackups, error) {
	funcName := GetFunctionName()

	info, err := os.Stat(rootPath)
	if err != nil {
		return LoadedBackups{}, fmt.Errorf("%s - %w", funcName, err)
	}

	if !info.IsDir() {
		if !strings.EqualFold(filepath.Ext(info.Name()), ".json") {
			return LoadedBackups{}, fmt.Errorf("%s - %s is not a json file", funcName, rootPath)
		}

		return loadBackupFile(rootPath)
	}

	files, err := os.ReadDir(rootPath)
	if err != nil {
		return LoadedBackups{}, fmt.Errorf("%s - %w", funcName, err)
	}

	var out LoadedBackups

	for _, f := range files {
		if f.IsDir() || !strings.EqualFold(filepath.Ext(f.Name()), ".json") {
			continue
		}

		got, err := loadBackupFile(filepath.Join(rootPath, f.Name()))
		if err != nil {
			return LoadedBackups{}, fmt.Errorf("%s - %w", funcName, err)
		}

		out.FrontDoor = append(out.FrontDoor, got.FrontDoor...)
		out.AppGW = append(out.AppGW, got.AppGW...)
	}

	return out, nil
}

func loadBackupFile(path string) (LoadedBackups, error) {
	funcName := GetFunctionName()
	logging.Debugf("%s | loading file %s", funcName, path)

	// #nosec
	data, err := os.ReadFile(path)
	if err != nil {
		return LoadedBackups{}, fmt.Errorf("%s - %w", funcName, err)
	}

	var peek wafTypePeek
	if err := json.Unmarshal(data, &peek); err != nil {
		return LoadedBackups{}, fmt.Errorf("%s - %w", funcName, err)
	}

	if peek.WAFType == WAFTypeAppGW {
		wp, err := LoadWrappedAppGWPolicyFromFile(data)
		if err != nil {
			return LoadedBackups{}, fmt.Errorf("%s - %w", funcName, err)
		}

		return LoadedBackups{AppGW: []WrappedAppGWPolicy{wp}}, nil
	}

	var wp WrappedPolicy
	if err := json.Unmarshal(data, &wp); err != nil {
		return LoadedBackups{}, fmt.Errorf("%s - %w", funcName, err)
	}

	if wp.Policy.Properties == nil {
		return LoadedBackups{}, fmt.Errorf("%s - wrapped policy is invalid", funcName)
	}

	return LoadedBackups{FrontDoor: []WrappedPolicy{wp}}, nil
}
