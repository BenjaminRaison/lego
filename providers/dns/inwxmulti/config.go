package inwxmulti

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
)

type InwxAccount struct {
	InwxUsername     string   `json:"username"`
	InwxPassword     string   `json:"password"`
	InwxSharedSecret string   `json:"sharedSecret"`
	Domains          []string `json:"-"`
}
type InwxConfig struct {
	DomainConfig map[string][]string `json:"domainConfig"`
}

func getAccounts(configFile string) ([]*InwxAccount, error) {
	configJson, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s', because %w", configFile, err)
	}

	var config InwxConfig
	err = json.Unmarshal(configJson, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file '%s', becaues %w", configFile, err)
	}

	if config.DomainConfig == nil || len(config.DomainConfig) == 0 {
		return nil, errors.New("invalid inwx configuration")
	}

	accounts := make([]*InwxAccount, 0)

	for accountConfig, domains := range config.DomainConfig {
		account, err := readAccount(accountConfig, domains)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}

	return accounts, nil
}

func readAccount(path string, domains []string) (*InwxAccount, error) {
	accountJson, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var account InwxAccount
	err = json.Unmarshal(accountJson, &account)
	if err != nil {
		return nil, err
	}

	if account.InwxUsername == "" || account.InwxPassword == "" {
		return nil, fmt.Errorf("missing inwx credentials in '%s'", path)
	}
	account.Domains = domains
	return &account, nil
}
