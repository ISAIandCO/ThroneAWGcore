package awg

import (
	"strings"
	"testing"
)

const (
	testPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	testPublicKey  = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	testPSK        = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
)

func TestParseValidConfig(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader(`
[Interface]
PrivateKey = ` + testPrivateKey + `
Address = 10.8.0.2/32, fd00::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111
MTU = 1280
Jc = 5
Jmin = 40
Jmax = 90
S1 = 10
S2 = 20
S3 = 30
S4 = 40
H1 = 100-200
H2 = 201-300
H3 = 301-400
H4 = 401-500
I1 = <b 0x0102>
I2 = <r 16>

[Peer]
PublicKey = ` + testPublicKey + `
PresharedKey = ` + testPSK + `
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.MTU != 1280 || cfg.Jc != 5 || cfg.H4 != "401-500" || cfg.I2 != "<r 16>" {
		t.Fatalf("AWG fields were not parsed: %+v", cfg)
	}
	if got := len(cfg.Peers); got != 1 {
		t.Fatalf("peer count = %d", got)
	}
	if got := cfg.Peers[0].PersistentKeepaliveInterval; got != 25 {
		t.Fatalf("keepalive = %d", got)
	}
}

func TestValidateMissingRequiredFields(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader(`
[Interface]
Address = 10.8.0.2/32

[Peer]
PublicKey = ` + testPublicKey + `
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestIPCGeneration(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader(`
[Interface]
PrivateKey = ` + testPrivateKey + `
Address = 10.8.0.2/32
Jc = 4
S1 = 10
H1 = 100-200
I1 = <b 0x0102>

[Peer]
PublicKey = ` + testPublicKey + `
PresharedKey = ` + testPSK + `
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepaliveInterval = 15

[Peer]
PublicKey = ` + testPublicKey + `
Endpoint = vpn.example.com:51821
AllowedIPs = 10.0.0.0/8
`))
	if err != nil {
		t.Fatal(err)
	}
	ipc, err := cfg.IPC()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"private_key=0000000000000000000000000000000000000000000000000000000000000000",
		"jc=4",
		"s1=10",
		"h1=100-200",
		"i1=<b 0x0102>",
		"public_key=0101010101010101010101010101010101010101010101010101010101010101",
		"preshared_key=0202020202020202020202020202020202020202020202020202020202020202",
		"endpoint=203.0.113.1:51820",
		"allowed_ip=0.0.0.0/0",
		"persistent_keepalive_interval=15",
		"endpoint=vpn.example.com:51821",
		"allowed_ip=10.0.0.0/8",
	} {
		if !strings.Contains(ipc, want) {
			t.Fatalf("IPC missing %q:\n%s", want, ipc)
		}
	}
}

func TestInvalidEndpoint(t *testing.T) {
	cfg, err := ParseConfig(strings.NewReader(`
[Interface]
PrivateKey = ` + testPrivateKey + `
Address = 10.8.0.2/32

[Peer]
PublicKey = ` + testPublicKey + `
Endpoint = missing-port
AllowedIPs = 0.0.0.0/0
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid endpoint error")
	}
}
