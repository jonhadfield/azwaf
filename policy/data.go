package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jonhadfield/azwaf/config"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/azwaf/session"
	"github.com/sirupsen/logrus"
)

// GetFrontDoorByID returns a front door instance for the provided id.
// It includes endpoints with any associated waf Policies.
func GetFrontDoorByID(s *session.Session, frontDoorID string) (frontDoor FrontDoor, err error) {
	funcName := GetFunctionName()
	ctx := context.Background()

	rID := config.ParseResourceID(frontDoorID)

	c, err := s.GetFrontDoorsClient(rID.SubscriptionID)
	if err != nil {
		return
	}

	rawFrontDoor, merr := c.Get(ctx, rID.ResourceGroup, rID.Name, nil)
	if merr != nil {
		return frontDoor, fmt.Errorf("%s - %s", funcName, merr.Error())
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
					return
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
	}, err
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
func PushPolicy(s *session.Session, i *PushPolicyInput) (err error) {
	funcName := GetFunctionName()

	logrus.Debugf("pushing policy %s...", *i.Policy.Name)

	ctx := context.Background()

	// check we're not missing a policies client for the Subscription
	err = s.GetFrontDoorPoliciesClient(i.Subscription)
	if err != nil {
		return
	}

	poller, merr := s.FrontDoorPoliciesClients[i.Subscription].BeginCreateOrUpdate(ctx, i.ResourceGroup, i.Name, i.Policy, nil)
	if merr != nil {
		return fmt.Errorf("%s - %s", funcName, merr.Error())
	}

	if i.Async {
		logrus.Info("asynchronous policy push started")

		return
	}

	if err != nil {
		log.Fatalf("%s | failed to finish the request: %v", funcName, err)
	}

	_, merr = poller.PollUntilDone(ctx, nil)
	if merr != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}

	logrus.Infof("policy %s updated", *i.Policy.Name)

	return
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

func LoadPolicyFromFile(f string) (p armfrontdoor.WebApplicationFirewallPolicy, err error) {
	// #nosec
	data, err := os.ReadFile(f)
	if err != nil {
		return
	}

	err = json.Unmarshal(data, &p)

	return
}

func LoadWrappedPolicyFromFile(f string) (wp WrappedPolicy, err error) {
	funcName := GetFunctionName()
	logrus.Debugf("%s | loading file %s", funcName, f)
	// #nosec
	data, err := os.ReadFile(f)
	if err != nil {
		err = fmt.Errorf("%s - %w", funcName, err)

		return
	}

	logrus.Debugf("%s | loaded %d bytes of data from %s", funcName, len(data), f)

	err = json.Unmarshal(data, &wp)
	if err != nil {
		err = fmt.Errorf("%s - %w", funcName, err)

		return
	}

	if wp.Policy.Properties == nil {
		err = fmt.Errorf("%s - wrapped policy is invalid", funcName)

		return
	}

	return wp, nil
}

type Action struct {
	ActionType string `yaml:"action"`
	Policy     string
	Paths      []string `yaml:"paths"`
	MaxRules   int      `yaml:"max-rules"`
	Nets       IPNets
}

func LoadBackupsFromPaths(paths []string) (wps []WrappedPolicy, err error) {
	funcName := GetFunctionName()

	if len(paths) == 0 {
		return nil, fmt.Errorf("%s - no paths provided", funcName)
	}

	for _, path := range paths {
		var pwps []WrappedPolicy
		pwps, err = LoadBackupsFromPath(path)
		if err != nil {
			return
		}

		wps = append(wps, pwps...)
	}

	logrus.Debugf("loaded %d Policy backups", len(wps))

	return
}

func LoadBackupsFromPath(path string) (wps []WrappedPolicy, err error) {
	funcName := GetFunctionName()

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%s - %w", funcName, err)
	}

	if err != nil {
		return nil, fmt.Errorf("%s - %w", funcName, err)
	}

	if !info.IsDir() {
		if !strings.EqualFold(filepath.Ext(info.Name()), ".json") {
			return
		}

		var wp WrappedPolicy

		wp, err = LoadWrappedPolicyFromFile(path)
		if err != nil {
			return
		}

		wps = append(wps, wp)

		return
	}

	var files []os.DirEntry

	files, err = os.ReadDir(path)
	if err != nil {
		return
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		if !strings.EqualFold(filepath.Ext(file.Name()), ".json") {
			continue
		}

		var wp WrappedPolicy

		wp, err = LoadWrappedPolicyFromFile(filepath.Join(path, info.Name()))
		if err != nil {
			return
		}

		wps = append(wps, wp)
	}

	logrus.Debugf("loaded %d Policy backups", len(wps))

	return
}
