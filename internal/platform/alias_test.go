package platform_test

import (
	"errors"
	"strings"
	"testing"

	"ssh-ui/internal/platform"
)

func TestValidateAliasAcceptsOnlyTheSafeCharacterSet(t *testing.T) {
	accepted := []string{"bastion", "web-01", "db.internal", "a", "A1_b", strings.Repeat("h", 64)}
	for _, alias := range accepted {
		if err := platform.ValidateAlias(alias); err != nil {
			t.Errorf("ValidateAlias(%q) = %v, want nil", alias, err)
		}
	}

	rejected := []string{
		"",
		strings.Repeat("h", 65),
		"-oProxyCommand=touch /tmp/pwned",
		"--",
		"host name",
		"host;touch /tmp/pwned",
		`host"quote`,
		"host'quote",
		"host$(id)",
		"host`id`",
		"host\\escape",
		"host\nnewline",
		"host\ttab",
		"*",
		"!negated",
		"user@host",
		"%d",
		"../escape",
		"ホスト",
		".leading",
	}
	for _, alias := range rejected {
		if err := platform.ValidateAlias(alias); !errors.Is(err, platform.ErrUnsafeAlias) {
			t.Errorf("ValidateAlias(%q) = %v, want ErrUnsafeAlias", alias, err)
		}
	}
}

func TestValidateHostnameAcceptsNamesAndAddressesOnly(t *testing.T) {
	accepted := []string{"example.com", "bastion-1.internal", "203.0.113.10", "2001:db8::1", "host_name"}
	for _, host := range accepted {
		if err := platform.ValidateHostname(host); err != nil {
			t.Errorf("ValidateHostname(%q) = %v, want nil", host, err)
		}
	}

	rejected := []string{"", "-p2222", "host name", "host;id", "[2001:db8::1]", "host/path", strings.Repeat("h", 256)}
	for _, host := range rejected {
		if err := platform.ValidateHostname(host); !errors.Is(err, platform.ErrUnsafeHostname) {
			t.Errorf("ValidateHostname(%q) = %v, want ErrUnsafeHostname", host, err)
		}
	}
}

func TestValidatePortRejectsValuesOutsideTheTCPRange(t *testing.T) {
	for _, port := range []int{1, 22, 65535} {
		if err := platform.ValidatePort(port); err != nil {
			t.Errorf("ValidatePort(%d) = %v, want nil", port, err)
		}
	}
	for _, port := range []int{0, -1, 65536, 100000} {
		if err := platform.ValidatePort(port); !errors.Is(err, platform.ErrUnsafePort) {
			t.Errorf("ValidatePort(%d) = %v, want ErrUnsafePort", port, err)
		}
	}
}
