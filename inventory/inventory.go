// Package inventory reads infra.yaml, the plan of everything: environments,
// hosts, services, networks, and how to reach each host. Every tool built on
// this module loads it through this package and resolves host addresses from
// the cloud provider's CLI at runtime, so nothing is typed twice.
package inventory

import (
	"regexp"
)

// Inventory is the parsed infra.yaml.
type Inventory struct {
	Project    string `yaml:"project"`
	DefaultEnv string `yaml:"default_env"`
	// Provider is the CLI that knows the servers (see ProviderCLI).
	Provider *Provider `yaml:"provider"`
	// Tokens is where the verification key for issued tokens lives.
	Tokens *Tokens `yaml:"tokens"`
	// SSH defaults for every host; environments and hosts override.
	SSH          SSHDefaults             `yaml:"ssh"`
	Vars         map[string]any          `yaml:"vars"`
	Environments map[string]*Environment `yaml:"environments"`

	// Path is where the file was read from. Relative paths in the file are
	// resolved against its directory.
	Path string `yaml:"-"`
}

// Provider names the CLI that resolves servers and the file it reads.
type Provider struct {
	// Command is the executable; default: what the tool passes to ProviderCLI.
	Command string `yaml:"command"`
	// File is the provider's own config, passed as --file (relative to infra.yaml).
	File string `yaml:"file"`
}

// Tokens configures token verification and the policy for token holders.
type Tokens struct {
	PublicKeyFile string `yaml:"public_key_file"`
	// PolicyFile is policy.yaml: what token holders may never do and what
	// needs an operator's approval. Default: policy.yaml next to infra.yaml
	// when it exists.
	PolicyFile string `yaml:"policy_file,omitempty"`
}

// SSHDefaults are inherited settings.
type SSHDefaults struct {
	User string `yaml:"user"`
	Port int    `yaml:"port"`
}

// Environment is one deployment target: prod, staging, ...
type Environment struct {
	// ProviderEnv is the provider's environment name. Default: the environment name.
	ProviderEnv string `yaml:"provider_env"`
	// Protected environments refuse every mutating command unless --confirm <env>
	// (or INFRA_CONFIRM=<env>) names them explicitly.
	Protected bool                `yaml:"protected"`
	Domain    string              `yaml:"domain"`
	SSH       SSHDefaults         `yaml:"ssh"`
	Vars      map[string]any      `yaml:"vars"`
	Hosts     map[string]*Host    `yaml:"hosts"`
	Services  map[string]*Service `yaml:"services"`
	Networks  map[string]*Network `yaml:"networks"`
}

// Host is one machine.
type Host struct {
	// Provider is the server name at the provider; default: the host name
	// when the inventory has a provider. "none" for a machine it does not own.
	Provider string `yaml:"provider"`
	// Address is the public IP or DNS name. Resolved from the provider when empty.
	Address        string   `yaml:"address"`
	PrivateAddress string   `yaml:"private_address"`
	VPNAddress     string   `yaml:"vpn_address"`
	SSH            HostSSH  `yaml:"ssh"`
	Roles          []string `yaml:"roles"`
	DNS            []string `yaml:"dns"`
	// Networks the host is a member of, by name. Derived from private/vpn
	// addresses when empty.
	Networks []string          `yaml:"networks"`
	Labels   map[string]string `yaml:"labels"`
	Vars     map[string]any    `yaml:"vars"`
}

// HostSSH says how to reach the host.
type HostSSH struct {
	User string `yaml:"user"`
	Port int    `yaml:"port"`
	// Via is the jump host (another host of the environment).
	Via string `yaml:"via"`
	// Address picks which address ssh uses: public (default when set), vpn, private.
	Address string `yaml:"address"`
}

// Service is something a deployment tool puts onto hosts.
type Service struct {
	Hosts []string `yaml:"hosts"`
	// Expose says who may reach the service: public (default), vpn (only
	// through the WireGuard network), private (only from the private network).
	// DNS, firewall and reverse proxy follow it.
	Expose    string            `yaml:"expose"`
	DependsOn []string          `yaml:"depends_on"`
	Ports     []Port            `yaml:"ports"`
	DNS       []string          `yaml:"dns"`
	Labels    map[string]string `yaml:"labels"`
	Vars      map[string]any    `yaml:"vars"`
}

// Port is a listening port of a service.
type Port struct {
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol"` // tcp (default) | udp
	// Public means reachable from the internet; otherwise private/vpn only.
	Public bool `yaml:"public"`
}

// Network is a private or VPN network.
type Network struct {
	Kind string `yaml:"kind"` // wireguard | private
	CIDR string `yaml:"cidr"`
	// Hub is the WireGuard hub host (kind wireguard).
	Hub string `yaml:"hub"`
	// Provider is the network's name at the provider (kind private).
	Provider string `yaml:"provider"`
}

// Address kinds for HostSSH.Address.
const (
	AddrPublic  = "public"
	AddrVPN     = "vpn"
	AddrPrivate = "private"
)

// Expose values.
const (
	ExposePublic  = "public"
	ExposeVPN     = "vpn"
	ExposePrivate = "private"
)

// Network kinds.
const (
	NetWireGuard = "wireguard"
	NetPrivate   = "private"
)

// ProviderNone marks a host the provider does not own.
const ProviderNone = "none"

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidName reports whether s is a hostname-shaped logical name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

var dnsRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// ValidDNS reports whether s is a fully qualified name (wildcard allowed).
func ValidDNS(s string) bool { return dnsRe.MatchString(s) }
