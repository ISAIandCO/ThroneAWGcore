package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	version4     = 0x04
	version5     = 0x05
	authNone     = 0x00
	authNoAccept = 0xff
	cmdConnect   = 0x01
	cmdUDP       = 0x03
	atypIPv4     = 0x01
	atypDomain   = 0x03
	atypIPv6     = 0x04
	repSuccess   = 0x00
	repFailure   = 0x01
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Server struct {
	listen  string
	dialer  Dialer
	verbose bool
	timeout time.Duration
}

type Options struct {
	Verbose bool
	Timeout time.Duration
}

func NewServer(listen string, dialer Dialer, opts ...Options) *Server {
	var cfg Options
	if len(opts) > 0 {
		cfg = opts[0]
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &Server{listen: listen, dialer: dialer, verbose: cfg.Verbose, timeout: cfg.Timeout}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, client net.Conn) {
	defer client.Close()

	req, err := readClientRequest(client)
	if err != nil {
		s.logf("request error from %s: %v", client.RemoteAddr(), err)
		return
	}
	s.logf("request cmd=%d version=%d address=%s from %s", req.cmd, req.version, req.address, client.RemoteAddr())

	switch req.cmd {
	case cmdConnect:
		s.handleConnect(ctx, client, req)
	case cmdUDP:
		if req.version != version5 {
			_ = writeReply(client, req.version, repFailure, nil)
			return
		}
		s.handleUDP(ctx, client)
	default:
		_ = writeReply(client, req.version, repFailure, nil)
	}
}

func (s *Server) handleConnect(ctx context.Context, client net.Conn, req request) {
	start := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	target, err := s.dialer.DialContext(dialCtx, "tcp", req.address)
	if err != nil {
		s.logf("tcp connect %s failed after %s: %v", req.address, time.Since(start).Round(time.Millisecond), err)
		_ = writeReply(client, req.version, repFailure, nil)
		return
	}
	defer target.Close()

	s.logf("tcp connect %s ok after %s", req.address, time.Since(start).Round(time.Millisecond))
	if err := writeReply(client, req.version, repSuccess, target.LocalAddr()); err != nil {
		return
	}
	proxy(client, target)
}

func (s *Server) handleUDP(ctx context.Context, client net.Conn) {
	host, _, err := net.SplitHostPort(client.LocalAddr().String())
	if err != nil || host == "" || host == "::" {
		host = "127.0.0.1"
	}
	udpConn, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		s.logf("udp associate listen failed: %v", err)
		_ = writeReply(client, version5, repFailure, nil)
		return
	}
	defer udpConn.Close()

	s.logf("udp associate listening on %s", udpConn.LocalAddr())
	if err := writeReply(client, version5, repSuccess, udpConn.LocalAddr()); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		_, _ = io.Copy(io.Discard, client)
		cancel()
		_ = udpConn.Close()
	}()

	relay := newUDPRelay(s.dialer, udpConn, s.logf)
	relay.serve(ctx)
}

func (s *Server) logf(format string, args ...any) {
	if s.verbose {
		fmt.Printf("socks: "+format+"\n", args...)
	}
}

type request struct {
	version byte
	cmd     byte
	address string
}

func readClientRequest(conn net.Conn) (request, error) {
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		return request{}, err
	}
	switch first[0] {
	case version5:
		if err := negotiate5(conn); err != nil {
			return request{}, err
		}
		req, err := readRequest5(conn)
		req.version = version5
		return req, err
	case version4:
		return readRequest4(conn)
	default:
		return request{}, fmt.Errorf("unsupported socks version %d", first[0])
	}
}

func negotiate5(conn net.Conn) error {
	var methodCount [1]byte
	if _, err := io.ReadFull(conn, methodCount[:]); err != nil {
		return err
	}
	methods := make([]byte, int(methodCount[0]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == authNone {
			_, err := conn.Write([]byte{version5, authNone})
			return err
		}
	}
	_, _ = conn.Write([]byte{version5, authNoAccept})
	return errors.New("no acceptable auth method")
}

func readRequest5(conn net.Conn) (request, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return request{}, err
	}
	if header[0] != version5 {
		return request{}, fmt.Errorf("unsupported socks version %d", header[0])
	}
	host, err := readAddr(conn, header[3])
	if err != nil {
		return request{}, err
	}
	portRaw := make([]byte, 2)
	if _, err := io.ReadFull(conn, portRaw); err != nil {
		return request{}, err
	}
	port := binary.BigEndian.Uint16(portRaw)
	return request{cmd: header[1], address: net.JoinHostPort(host, strconv.Itoa(int(port)))}, nil
}

func readRequest4(conn net.Conn) (request, error) {
	header := make([]byte, 7)
	if _, err := io.ReadFull(conn, header); err != nil {
		return request{}, err
	}
	cmd := header[0]
	port := binary.BigEndian.Uint16(header[1:3])
	ip := net.IPv4(header[3], header[4], header[5], header[6])
	if _, err := readNullTerminated(conn); err != nil {
		return request{}, err
	}

	host := ip.String()
	if header[3] == 0 && header[4] == 0 && header[5] == 0 && header[6] != 0 {
		domain, err := readNullTerminated(conn)
		if err != nil {
			return request{}, err
		}
		host = domain
	}
	return request{
		version: version4,
		cmd:     cmd,
		address: net.JoinHostPort(host, strconv.Itoa(int(port))),
	}, nil
}

func readNullTerminated(r io.Reader) (string, error) {
	var out []byte
	var b [1]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		if b[0] == 0 {
			return string(out), nil
		}
		out = append(out, b[0])
		if len(out) > 4096 {
			return "", errors.New("null-terminated field too long")
		}
	}
}

func readAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		raw := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, raw); err != nil {
			return "", err
		}
		return net.IP(raw).String(), nil
	case atypIPv6:
		raw := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, raw); err != nil {
			return "", err
		}
		return net.IP(raw).String(), nil
	case atypDomain:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return "", err
		}
		raw := make([]byte, int(size[0]))
		if _, err := io.ReadFull(r, raw); err != nil {
			return "", err
		}
		return string(raw), nil
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
}

func writeReply(conn net.Conn, version, rep byte, addr net.Addr) error {
	if version == version4 {
		return writeReply4(conn, rep)
	}
	return writeReply5(conn, rep, addr)
}

func writeReply5(conn net.Conn, rep byte, addr net.Addr) error {
	host := "0.0.0.0"
	port := 0
	if addr != nil {
		if h, p, err := net.SplitHostPort(addr.String()); err == nil {
			host = h
			port, _ = strconv.Atoi(p)
		}
	}
	ip := net.ParseIP(host)
	resp := []byte{version5, rep, 0x00}
	if ip4 := ip.To4(); ip4 != nil {
		resp = append(resp, atypIPv4)
		resp = append(resp, ip4...)
	} else if ip16 := ip.To16(); ip16 != nil {
		resp = append(resp, atypIPv6)
		resp = append(resp, ip16...)
	} else {
		resp = append(resp, atypIPv4, 0, 0, 0, 0)
	}
	var portRaw [2]byte
	binary.BigEndian.PutUint16(portRaw[:], uint16(port))
	resp = append(resp, portRaw[:]...)
	_, err := conn.Write(resp)
	return err
}

func writeReply4(conn net.Conn, rep byte) error {
	code := byte(0x5b)
	if rep == repSuccess {
		code = 0x5a
	}
	_, err := conn.Write([]byte{0x00, code, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return err
}

func proxy(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go copyAndClose(&wg, a, b)
	go copyAndClose(&wg, b, a)
	wg.Wait()
}

func copyAndClose(wg *sync.WaitGroup, dst, src net.Conn) {
	defer wg.Done()
	_, _ = io.Copy(dst, src)
	if c, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = c.CloseWrite()
	} else {
		_ = dst.Close()
	}
}

type udpRelay struct {
	dialer Dialer
	packet net.PacketConn
	mu     sync.Mutex
	flows  map[string]*udpFlow
	logf   func(string, ...any)
}

type udpFlow struct {
	target net.Conn
	client net.Addr
}

func newUDPRelay(dialer Dialer, packet net.PacketConn, logf func(string, ...any)) *udpRelay {
	return &udpRelay{dialer: dialer, packet: packet, flows: map[string]*udpFlow{}, logf: logf}
}

func (r *udpRelay) serve(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		_ = r.packet.SetReadDeadline(time.Now().Add(time.Second))
		n, clientAddr, err := r.packet.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || isTimeout(err) {
				if ctx.Err() != nil {
					r.close()
					return
				}
				continue
			}
			r.close()
			return
		}
		udpReq, err := parseUDPDatagram(buf[:n])
		if err != nil {
			r.logf("udp parse from %s failed: %v", clientAddr, err)
			continue
		}
		flow, err := r.flow(ctx, clientAddr, udpReq.address)
		if err != nil {
			r.logf("udp connect %s failed: %v", udpReq.address, err)
			continue
		}
		_, _ = flow.target.Write(udpReq.payload)
	}
}

func (r *udpRelay) flow(ctx context.Context, clientAddr net.Addr, targetAddr string) (*udpFlow, error) {
	key := clientAddr.String() + "|" + targetAddr
	r.mu.Lock()
	if flow := r.flows[key]; flow != nil {
		r.mu.Unlock()
		return flow, nil
	}
	r.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	target, err := r.dialer.DialContext(dialCtx, "udp", targetAddr)
	if err != nil {
		return nil, err
	}
	flow := &udpFlow{target: target, client: clientAddr}

	r.mu.Lock()
	r.flows[key] = flow
	r.mu.Unlock()

	go r.readResponses(key, flow, targetAddr)
	return flow, nil
}

func (r *udpRelay) readResponses(key string, flow *udpFlow, targetAddr string) {
	defer func() {
		_ = flow.target.Close()
		r.mu.Lock()
		delete(r.flows, key)
		r.mu.Unlock()
	}()

	buf := make([]byte, 65535)
	for {
		_ = flow.target.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, err := flow.target.Read(buf)
		if err != nil {
			return
		}
		resp, err := buildUDPDatagram(targetAddr, buf[:n])
		if err != nil {
			return
		}
		_, _ = r.packet.WriteTo(resp, flow.client)
	}
}

func (r *udpRelay) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, flow := range r.flows {
		_ = flow.target.Close()
		delete(r.flows, key)
	}
}

type udpDatagram struct {
	address string
	payload []byte
}

func parseUDPDatagram(data []byte) (udpDatagram, error) {
	if len(data) < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
		return udpDatagram{}, errors.New("invalid udp header")
	}
	host, offset, err := parseAddrBytes(data, 3)
	if err != nil {
		return udpDatagram{}, err
	}
	if len(data) < offset+2 {
		return udpDatagram{}, errors.New("missing udp port")
	}
	port := binary.BigEndian.Uint16(data[offset : offset+2])
	return udpDatagram{
		address: net.JoinHostPort(host, strconv.Itoa(int(port))),
		payload: data[offset+2:],
	}, nil
}

func parseAddrBytes(data []byte, offset int) (string, int, error) {
	if len(data) <= offset {
		return "", 0, errors.New("missing address type")
	}
	atyp := data[offset]
	offset++
	switch atyp {
	case atypIPv4:
		if len(data) < offset+net.IPv4len {
			return "", 0, errors.New("short ipv4 address")
		}
		return net.IP(data[offset : offset+net.IPv4len]).String(), offset + net.IPv4len, nil
	case atypIPv6:
		if len(data) < offset+net.IPv6len {
			return "", 0, errors.New("short ipv6 address")
		}
		return net.IP(data[offset : offset+net.IPv6len]).String(), offset + net.IPv6len, nil
	case atypDomain:
		if len(data) <= offset {
			return "", 0, errors.New("missing domain length")
		}
		size := int(data[offset])
		offset++
		if len(data) < offset+size {
			return "", 0, errors.New("short domain")
		}
		return string(data[offset : offset+size]), offset + size, nil
	default:
		return "", 0, fmt.Errorf("unsupported address type %d", atyp)
	}
}

func buildUDPDatagram(address string, payload []byte) ([]byte, error) {
	host, portRaw, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return nil, err
	}
	out := []byte{0, 0, 0}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		out = append(out, atypIPv4)
		out = append(out, ip4...)
	} else if ip16 := ip.To16(); ip16 != nil {
		out = append(out, atypIPv6)
		out = append(out, ip16...)
	} else {
		if len(host) > 255 {
			return nil, errors.New("domain too long")
		}
		out = append(out, atypDomain, byte(len(host)))
		out = append(out, host...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	out = append(out, portBuf[:]...)
	out = append(out, payload...)
	return out, nil
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
