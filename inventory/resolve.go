package inventory

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Resolved is one environment with every reference followed and every
// address known (as far as the provider could tell).
type Resolved struct {
	Project     string               `json:"project"`
	Env         string               `json:"env"`
	Domain      string               `json:"domain,omitempty"`
	ProviderEnv string               `json:"provider_env,omitempty"`
	Hosts       map[string]*RHost    `json:"hosts"`
	Services    map[string]*RService `json:"services"`
	Networks    map[string]*RNetwork `json:"networks"`
	// Warnings are non-fatal resolution findings (provider unavailable, ...).
	Warnings []string `json:"warnings,omitempty"`
	// ProviderOrphans are the provider's servers of the environment that no host claims.
	ProviderOrphans []string `json:"provider_orphans,omitempty"`
}

// RHost is a resolved host.
type RHost struct {
	Name           string            `json:"name"`
	Env            string            `json:"env"`
	Address        string            `json:"address,omitempty"`
	AddressSource  string            `json:"address_source"` // inventory | provider | unresolved | none
	IPv6           string            `json:"ipv6,omitempty"`
	PrivateAddress string            `json:"private_address,omitempty"`
	VPNAddress     string            `json:"vpn_address,omitempty"`
	Provider       *RProvider        `json:"provider,omitempty"`
	SSH            RSSH              `json:"ssh"`
	Route          []Hop             `json:"route"`
	Roles          []string          `json:"roles"`
	Services       []string          `json:"services"`
	DNS            []string          `json:"dns,omitempty"`
	Networks       []string          `json:"networks,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Vars           map[string]any    `json:"vars,omitempty"`
}

// RProvider is what the provider knows about the server.
type RProvider struct {
	Name     string `json:"name"`
	ID       int64  `json:"id,omitempty"`
	State    string `json:"state,omitempty"`
	Type     string `json:"server_type,omitempty"`
	Location string `json:"location,omitempty"`
	// Missing: the inventory expects the server but the provider has none.
	Missing bool `json:"missing,omitempty"`
}

// RSSH is the effective ssh setting.
type RSSH struct {
	User        string `json:"user"`
	Port        int    `json:"port"`
	Via         string `json:"via,omitempty"`
	AddressKind string `json:"address_kind"` // public | vpn | private
	Address     string `json:"address,omitempty"`
}

// Hop is one ssh hop; the last hop is the host itself.
type Hop struct {
	Host    string `json:"host"`
	Address string `json:"address"`
	User    string `json:"user"`
	Port    int    `json:"port"`
}

// RService is a resolved service.
type RService struct {
	Name      string            `json:"name"`
	Env       string            `json:"env"`
	Hosts     []string          `json:"hosts"`
	DependsOn []string          `json:"depends_on,omitempty"`
	Ports     []Port            `json:"ports,omitempty"`
	DNS       []string          `json:"dns,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Vars      map[string]any    `json:"vars,omitempty"`
}

// RNetwork is a resolved network.
type RNetwork struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	CIDR     string   `json:"cidr,omitempty"`
	Hub      string   `json:"hub,omitempty"`
	Provider string   `json:"provider,omitempty"`
	Members  []string `json:"members"`
}

// Lookup provides the provider's view. Nil means offline.
type Lookup interface {
	// Servers returns the servers of a provider environment.
	Servers(ctx context.Context, p Provider, env string) ([]Server, error)
}

// Server is what the provider reports for a server.
type Server struct {
	Name     string
	ID       int64
	State    string
	Type     string
	Location string
	IPv4     string
	IPv6     string
}

// Resolve builds the resolved view of one environment. With lookup nil (or
// --offline) provider hosts keep AddressSource "unresolved". A lookup failure is
// a warning, not an error: the inventory is still useful without addresses.
func (inv *Inventory) Resolve(ctx context.Context, envName string, lookup Lookup) (*Resolved, error) {
	env, ok := inv.Environments[envName]
	if !ok {
		return nil, fmt.Errorf("environment %q is not in the inventory", envName)
	}
	r := &Resolved{Project: inv.Project, Env: envName, Domain: env.Domain, ProviderEnv: env.ProviderEnv,
		Hosts: map[string]*RHost{}, Services: map[string]*RService{}, Networks: map[string]*RNetwork{}}
	if r.ProviderEnv == "" {
		r.ProviderEnv = envName
	}

	var servers map[string]Server
	needProvider := false
	for _, h := range env.Hosts {
		if h != nil && h.OnProvider(inv) {
			needProvider = true
		}
	}
	if needProvider && lookup != nil && inv.Provider != nil {
		p := *inv.Provider
		p.File = inv.ProviderFile()
		list, err := lookup.Servers(ctx, p, r.ProviderEnv)
		if err != nil {
			r.Warnings = append(r.Warnings, "provider: "+err.Error())
		} else {
			servers = map[string]Server{}
			for _, s := range list {
				servers[s.Name] = s
			}
		}
	} else if needProvider && inv.Provider == nil {
		r.Warnings = append(r.Warnings, "hosts reference provider servers but the inventory has no provider: {...}")
	}

	for _, name := range sortedKeys(env.Hosts) {
		h := env.Hosts[name]
		if h == nil {
			h = &Host{}
		}
		rh := &RHost{Name: name, Env: envName, Address: h.Address, PrivateAddress: h.PrivateAddress, VPNAddress: h.VPNAddress,
			Roles: nonNil(h.Roles), Services: []string{}, DNS: h.DNS, Labels: h.Labels, Networks: h.Networks,
			Vars: merge(inv.Vars, env.Vars, h.Vars)}
		if rh.Address != "" {
			rh.AddressSource = "inventory"
		} else {
			rh.AddressSource = "none"
		}
		if hn := h.ProviderName(inv, name); hn != "" {
			rh.Provider = &RProvider{Name: hn}
			if servers != nil {
				if s, ok := servers[hn]; ok {
					rh.Provider.ID, rh.Provider.State, rh.Provider.Type, rh.Provider.Location = s.ID, s.State, s.Type, s.Location
					if rh.Address == "" && s.IPv4 != "" {
						rh.Address, rh.AddressSource = s.IPv4, "provider"
					}
					rh.IPv6 = s.IPv6
					delete(servers, hn)
				} else {
					rh.Provider.Missing = true
					if rh.Address == "" {
						rh.AddressSource = "unresolved"
					}
				}
			} else if rh.Address == "" {
				rh.AddressSource = "unresolved"
			}
		}
		rh.SSH = effectiveSSH(inv, env, h, rh)
		if len(rh.Networks) == 0 {
			rh.Networks = memberOf(env, name, h)
		}
		r.Hosts[name] = rh
	}
	if servers != nil {
		for n := range servers {
			r.ProviderOrphans = append(r.ProviderOrphans, n)
		}
		sort.Strings(r.ProviderOrphans)
	}
	for _, name := range r.hostNames() {
		r.Hosts[name].Route = r.route(name)
	}

	for _, name := range sortedKeys(env.Services) {
		s := env.Services[name]
		if s == nil {
			s = &Service{}
		}
		rs := &RService{Name: name, Env: envName, Hosts: nonNil(s.Hosts), DependsOn: s.DependsOn, Ports: s.Ports, DNS: s.DNS,
			Labels: s.Labels, Vars: merge(inv.Vars, env.Vars, s.Vars)}
		r.Services[name] = rs
		for _, h := range s.Hosts {
			if rh, ok := r.Hosts[h]; ok {
				rh.Services = append(rh.Services, name)
			}
		}
	}
	for _, name := range sortedKeys(env.Networks) {
		n := env.Networks[name]
		if n == nil {
			continue
		}
		rn := &RNetwork{Name: name, Kind: n.Kind, CIDR: n.CIDR, Hub: n.Hub, Provider: n.Provider, Members: []string{}}
		for _, h := range r.hostNames() {
			for _, m := range r.Hosts[h].Networks {
				if m == name {
					rn.Members = append(rn.Members, h)
				}
			}
		}
		r.Networks[name] = rn
	}
	return r, nil
}

func effectiveSSH(inv *Inventory, env *Environment, h *Host, rh *RHost) RSSH {
	s := RSSH{User: "root", Port: 22, Via: h.SSH.Via}
	for _, d := range []SSHDefaults{inv.SSH, env.SSH, {User: h.SSH.User, Port: h.SSH.Port}} {
		if d.User != "" {
			s.User = d.User
		}
		if d.Port != 0 {
			s.Port = d.Port
		}
	}
	s.AddressKind = h.SSH.Address
	if s.AddressKind == "" {
		switch {
		case rh.Address != "" || rh.AddressSource == "unresolved":
			s.AddressKind = AddrPublic
		case rh.VPNAddress != "":
			s.AddressKind = AddrVPN
		case rh.PrivateAddress != "":
			s.AddressKind = AddrPrivate
		default:
			s.AddressKind = AddrPublic
		}
	}
	switch s.AddressKind {
	case AddrVPN:
		s.Address = rh.VPNAddress
	case AddrPrivate:
		s.Address = rh.PrivateAddress
	default:
		s.Address = rh.Address
	}
	return s
}

func memberOf(env *Environment, name string, h *Host) []string {
	var out []string
	for _, n := range sortedKeys(env.Networks) {
		net := env.Networks[n]
		if net == nil {
			continue
		}
		switch net.Kind {
		case NetWireGuard:
			if h.VPNAddress != "" || net.Hub == name {
				out = append(out, n)
			}
		case NetPrivate:
			if h.PrivateAddress != "" {
				out = append(out, n)
			}
		}
	}
	return out
}

// route returns the hops to reach name, ending with name itself. A hop
// with an empty address means the route is incomplete (unresolved host).
func (r *Resolved) route(name string) []Hop {
	var hops []Hop
	seen := map[string]bool{}
	cur := name
	for cur != "" && !seen[cur] {
		seen[cur] = true
		h := r.Hosts[cur]
		if h == nil {
			break
		}
		hops = append([]Hop{{Host: cur, Address: h.SSH.Address, User: h.SSH.User, Port: h.SSH.Port}}, hops...)
		cur = h.SSH.Via
	}
	return hops
}

// HostNames returns the host names sorted.
func (r *Resolved) HostNames() []string { return r.hostNames() }

func (r *Resolved) hostNames() []string { return sortedKeys(r.Hosts) }

// ServiceNames returns the service names sorted.
func (r *Resolved) ServiceNames() []string { return sortedKeys(r.Services) }

// NetworkNames returns the network names sorted.
func (r *Resolved) NetworkNames() []string { return sortedKeys(r.Networks) }

// Reachable reports whether every hop of the host's route has an address.
func (h *RHost) Reachable() bool {
	if len(h.Route) == 0 {
		return false
	}
	for _, hop := range h.Route {
		if hop.Address == "" {
			return false
		}
	}
	return true
}

// HasRole reports whether the host has the role.
func (h *RHost) HasRole(role string) bool {
	for _, r := range h.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// RouteString renders "hub-1 -> web-1" for tables.
func (h *RHost) RouteString() string {
	if len(h.Route) <= 1 {
		return "direct"
	}
	parts := make([]string, 0, len(h.Route)-1)
	for _, hop := range h.Route[:len(h.Route)-1] {
		parts = append(parts, hop.Host)
	}
	return "via " + strings.Join(parts, " -> ")
}

// Target is "<env>/<name>", the string token scopes match against.
func (h *RHost) Target() string { return h.Env + "/" + h.Name }

// Target is "<env>/<name>".
func (s *RService) Target() string { return s.Env + "/" + s.Name }

func merge(layers ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, l := range layers {
		for k, v := range l {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
