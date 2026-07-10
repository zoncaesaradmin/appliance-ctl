package helm

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type chartValues struct {
	Secrets struct {
		KeysSecretName string `yaml:"keysSecretName"`
	} `yaml:"secrets"`
	Persistence struct {
		Enabled          bool   `yaml:"enabled"`
		StorageClassName string `yaml:"storageClassName"`
	} `yaml:"persistence"`
}

func loadChartValues(valuesPath string) (chartValues, error) {
	data, err := os.ReadFile(valuesPath)
	if err != nil {
		return chartValues{}, fmt.Errorf("helm: read chart values %s: %w", valuesPath, err)
	}

	var values chartValues
	if err := yaml.Unmarshal(data, &values); err != nil {
		return chartValues{}, fmt.Errorf("helm: parse chart values %s: %w", valuesPath, err)
	}

	values.Secrets.KeysSecretName = strings.TrimSpace(values.Secrets.KeysSecretName)
	values.Persistence.StorageClassName = strings.TrimSpace(values.Persistence.StorageClassName)
	return values, nil
}
