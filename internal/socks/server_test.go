package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
)

type fakeDialer struct {
	mu       sync.Mutex
	requests []string
}

func (d *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.requests = append(d.requests, network+" "+address)
	d.mu.Unlock()

	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	return client, nil
}

func (d *fakeDialer) lastRequest() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.requests) == 0 {
		return ""
	}
	return d.requests[len(d.requests)-1]
}

func TestConnectRoutesDomainThroughDialer(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	dialer := &fakeDialer{}
	srv := NewServer("127.0.0.1:0", dialer)
	go srv.handleConn(context.Background(), serverConn)

	_, _ = client.Write([]byte{0x05, 0x01, 0x00})
	handshake := make([]byte, 2)
	if _, err := io.ReadFull(client, handshake); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(handshake, []byte{0x05, 0x00}) {
		t.Fatalf("handshake = %v", handshake)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))}
	req = append(req, []byte("example.com")...)
	req = append(req, 0x01, 0xbb)
	_, _ = client.Write(req)

	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("reply = %v", reply)
	}
	if got := dialer.lastRequest(); got != "tcp example.com:443" {
		t.Fatalf("dial request = %q", got)
	}

	_, _ = client.Write([]byte("ping"))
	echo := make([]byte, 4)
	if _, err := io.ReadFull(client, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "ping" {
		t.Fatalf("echo = %q", echo)
	}
}

func TestConnectSOCKS4A(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	dialer := &fakeDialer{}
	srv := NewServer("127.0.0.1:0", dialer)
	go srv.handleConn(context.Background(), serverConn)

	req := []byte{0x04, 0x01, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00}
	req = append(req, []byte("example.com")...)
	req = append(req, 0x00)
	_, _ = client.Write(req)

	reply := make([]byte, 8)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x5a {
		t.Fatalf("reply = %v", reply)
	}
	if got := dialer.lastRequest(); got != "tcp example.com:443" {
		t.Fatalf("dial request = %q", got)
	}
}

func TestUDPDatagramFramingIPv4(t *testing.T) {
	packet, err := buildUDPDatagram("1.2.3.4:53", []byte("dns"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseUDPDatagram(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.address != "1.2.3.4:53" || string(got.payload) != "dns" {
		t.Fatalf("parsed datagram = %+v", got)
	}
}

func TestUDPDatagramFramingDomain(t *testing.T) {
	packet, err := buildUDPDatagram("dns.example:5353", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseUDPDatagram(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.address != "dns.example:5353" || string(got.payload) != "payload" {
		t.Fatalf("parsed datagram = %+v", got)
	}
}

func TestParseUDPRejectsFragments(t *testing.T) {
	packet := []byte{0, 0, 1, atypIPv4, 1, 2, 3, 4, 0, 53}
	if _, err := parseUDPDatagram(packet); err == nil {
		t.Fatal("expected fragmented datagram to be rejected")
	}
}

func TestReadRequestIPv4(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00})
		handshake := make([]byte, 2)
		_, _ = io.ReadFull(client, handshake)
		req := []byte{0x05, 0x01, 0x00, atypIPv4, 127, 0, 0, 1}
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], 8080)
		req = append(req, port[:]...)
		_, _ = client.Write(req)
	}()

	got, err := readClientRequest(server)
	if err != nil {
		t.Fatal(err)
	}
	if got.address != "127.0.0.1:8080" {
		t.Fatalf("address = %q", got.address)
	}
}
