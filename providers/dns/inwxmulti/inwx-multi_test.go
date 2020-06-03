package inwxmulti

import (
	"testing"

	"github.com/go-acme/lego/v4/platform/tester"
	"github.com/stretchr/testify/require"
)

const envDomain = envNamespace + "DOMAIN"

var envTest = tester.NewEnvTest(
	EnvConfig,
	EnvSandbox,
	EnvTTL).
	WithDomain(envDomain).
	WithLiveTestRequirements(EnvConfig, envDomain)

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				EnvConfig: "data/accounts.json",
			},
		},
		{
			desc: "missing config",
			envVars: map[string]string{
				EnvConfig: "",
			},
			expected: "inwx-multi: some credentials information are missing: INWX_CONFIG",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			defer envTest.RestoreEnv()
			envTest.ClearEnv()

			envTest.Apply(test.envVars)

			p, err := NewDNSProvider()

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.clients)
				require.NotNil(t, p.SharedSecrets)
				require.Equal(t, 3, len(p.clients))
				require.Equal(t, 3, len(p.SharedSecrets))
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestGetAccountDomain(t *testing.T) {
	envTest.Apply(map[string]string{EnvConfig: "data/accounts.json"})
	provider, err := NewDNSProvider()
	require.NoError(t, err)

	domains := []string{"example.com", "sub.example.com", "another.sub.domain.example.org"}
	for _, domain := range domains {
		ad, err := provider.getAccountDomain(domain)
		require.NoError(t, err)
		require.NotNil(t, ad)
	}
}
