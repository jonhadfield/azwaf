package session

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/logging"
)

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

type FileConfig struct {
	PolicyAliases map[string]string `yaml:"policy_aliases"`
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
