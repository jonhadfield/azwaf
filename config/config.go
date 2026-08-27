package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/logging"
)

// ParseResourceID accepts an azure resource ID as a string and returns a struct instance containing the components.
func ParseResourceID(rawID string) ResourceID {
	components := strings.Split(rawID, "/")
	if len(components) != ResourceIDComponents {
		return ResourceID{}
	}

	return ResourceID{
		SubscriptionID: components[2],
		ResourceGroup:  components[4],
		Provider:       components[6],
		ResourceType:   components[7],
		Name:           components[8],
		Raw:            rawID,
	}
}

func LoadFileConfig(path string) (config FileConfig, err error) {
	if path == "" {
		return config, nil
	}

	b, err := ReadFileBytes(path)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(b, &config)

	return config, err
}

type ResourceID struct {
	SubscriptionID string
	ResourceGroup  string
	Provider       string
	ResourceType   string
	Name           string
	Raw            string
}

func NewResourceID(subID, rg, provider, name string) ResourceID {
	return ResourceID{
		SubscriptionID: subID,
		ResourceGroup:  rg,
		Provider:       provider,
		Name:           name,
		Raw: fmt.Sprintf(
			"/subscriptions/%s/resourceGroups/%s/providers/%s/%s",
			subID, rg, provider, name,
		),
	}
}

type FileConfig struct {
	PolicyAliases map[string]string `yaml:"policy_aliases"`
}

func ReadFileBytes(path string) (content []byte, err error) {
	funcName := helpers.GetFunctionName()

	logging.Debugf("%s | reading %s", funcName, path)

	if _, err = os.Stat(path); err != nil {
		err = fmt.Errorf("%s - %w", funcName, err)

		return
	}

	// #nosec
	content, err = os.ReadFile(path)
	if err != nil {
		err = fmt.Errorf("%s - %w", funcName, err)

		return
	}

	return
}
