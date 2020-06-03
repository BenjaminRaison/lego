// Package inwx implements a DNS provider for solving the DNS-01 challenge using inwx dom robot
package inwxmulti

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/nrdcg/goinwx"
	"github.com/pquerna/otp/totp"
)

// Environment variables names.
const (
	envNamespace = "INWX_"

	EnvConfig  = envNamespace + "CONFIG"
	EnvSandbox = envNamespace + "SANDBOX"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	Sandbox            bool
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	TTL                int
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, 300),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
		Sandbox:            env.GetOrDefaultBool(EnvSandbox, false),
	}
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config        *Config
	clients       map[string]*goinwx.Client
	SharedSecrets map[string]string
}

// NewDNSProvider returns a DNSProvider instance configured for Dyn DNS.
// Configuration must be passed in the environment variables:
// INWX_CONFIG
func NewDNSProvider() (*DNSProvider, error) {
	config := NewDefaultConfig()
	return NewDNSProviderConfig(config)
}

// NewDNSProviderConfig return a DNSProvider instance configured for Dyn DNS.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("inwx-multi: the configuration of the DNS provider is nil")
	}

	values, err := env.Get(EnvConfig)
	if err != nil {
		return nil, fmt.Errorf("inwx-multi: %w", err)
	}

	if config.Sandbox {
		log.Infof("inwx-multi: sandbox mode is enabled")
	}

	provider := &DNSProvider{config: config, clients: make(map[string]*goinwx.Client), SharedSecrets: make(map[string]string)}
	err = provider.addAccountConfig(values[EnvConfig], &goinwx.ClientOptions{Sandbox: config.Sandbox})
	if err != nil {
		return nil, fmt.Errorf("inwx-multi: %w", err)
	}

	return provider, nil
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, _, keyAuth string) error {
	accountDomain, err := d.getAccountDomain(domain)
	if err != nil {
		return fmt.Errorf("inwx-multi: %w", err)
	}

	fqdn, value := dns01.GetRecord(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(fqdn)
	if err != nil {
		return fmt.Errorf("inwx-multi: %w", err)
	}

	info, err := d.clients[accountDomain].Account.Login()
	if err != nil {
		return fmt.Errorf("inwx-multi: %w", err)
	}

	defer func() {
		errL := d.clients[accountDomain].Account.Logout()
		if errL != nil {
			log.Infof("inwx-multi: failed to logout: %v", errL)
		}
	}()

	err = d.twoFactorAuth(info, accountDomain)
	if err != nil {
		return fmt.Errorf("inwx-multi: %w", err)
	}

	var request = &goinwx.NameserverRecordRequest{
		Domain:  dns01.UnFqdn(authZone),
		Name:    dns01.UnFqdn(fqdn),
		Type:    "TXT",
		Content: value,
		TTL:     d.config.TTL,
	}

	_, err = d.clients[accountDomain].Nameservers.CreateRecord(request)
	if err != nil {
		switch er := err.(type) {
		case *goinwx.ErrorResponse:
			if er.Message == "Object exists" {
				return nil
			}
			return fmt.Errorf("inwx-multi: %w", err)
		default:
			return fmt.Errorf("inwx-multi: %w", err)
		}
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, _, keyAuth string) error {
	accountDomain, err := d.getAccountDomain(domain)
	if err != nil {
		return fmt.Errorf("inwx-multi: %w", err)
	}

	fqdn, _ := dns01.GetRecord(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(fqdn)
	if err != nil {
		return fmt.Errorf("inwx-multi: %w", err)
	}

	info, err := d.clients[accountDomain].Account.Login()
	if err != nil {
		return fmt.Errorf("inwx-multi: %w", err)
	}

	defer func() {
		errL := d.clients[accountDomain].Account.Logout()
		if errL != nil {
			log.Infof("inwx-multi: failed to logout: %v", errL)
		}
	}()

	err = d.twoFactorAuth(info, accountDomain)
	if err != nil {
		return fmt.Errorf("inwx-multi: %w", err)
	}

	response, err := d.clients[accountDomain].Nameservers.Info(&goinwx.NameserverInfoRequest{
		Domain: dns01.UnFqdn(authZone),
		Name:   dns01.UnFqdn(fqdn),
		Type:   "TXT",
	})
	if err != nil {
		return fmt.Errorf("inwx-multi: %w", err)
	}

	var lastErr error
	for _, record := range response.Records {
		err = d.clients[accountDomain].Nameservers.DeleteRecord(record.ID)
		if err != nil {
			lastErr = fmt.Errorf("inwx-multi: %w", err)
		}
	}
	return lastErr
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

func (d *DNSProvider) twoFactorAuth(info *goinwx.LoginResponse, accountDomain string) error {
	if info.TFA != "GOOGLE-AUTH" {
		return nil
	}

	if d.SharedSecrets[accountDomain] == "" {
		return errors.New("two factor authentication but no shared secret is given")
	}

	tan, err := totp.GenerateCode(d.SharedSecrets[accountDomain], time.Now())
	if err != nil {
		return err
	}

	return d.clients[accountDomain].Account.Unlock(tan)
}

func (d *DNSProvider) getAccountDomain(domain string) (string, error) {
	for accountDomain := range d.clients {
		if strings.HasSuffix(domain, accountDomain) {
			return accountDomain, nil
		}
	}
	return "", fmt.Errorf("inwx-multi: no account configuration for %s", domain)
}

func (d *DNSProvider) addAccountConfig(configFile string, opts *goinwx.ClientOptions) error {
	accounts, err := getAccounts(configFile)
	if err != nil {
		return fmt.Errorf("inwx-multi: %w", err)
	}

	for _, account := range accounts {
		client := goinwx.NewClient(account.InwxUsername, account.InwxPassword, opts)
		for _, domain := range account.Domains {
			d.clients[domain] = client
			d.SharedSecrets[domain] = account.InwxSharedSecret
		}
	}
	return nil
}
