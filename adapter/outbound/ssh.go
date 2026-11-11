package outbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/randv2"
	"github.com/metacubex/ssh"
)

type Ssh struct {
	*Base

	option *SshOption

	config *ssh.ClientConfig
	client *ssh.Client
	kick   chan struct{} // 当前 client 的 keepalive 立即探测信号，与 client 同时设置
	cMutex sync.Mutex
}

// ssh 层心跳，类似 OpenSSH 的 ServerAliveInterval。底层 TCP 半死（睡眠唤醒、换网、
// 中间 NAT 丢表）时，没有心跳要等内核 keepalive 放弃（实测约 140s），期间所有新连接
// 都复用这条死 transport。心跳无回复才关 transport；开 channel 失败只触发一次立即探测，
// 不直接丢 client，避免误伤同节点上仍正常的会话。
const (
	SSH_KEEPALIVE_INTERVAL = 10 * time.Second
	SSH_KEEPALIVE_TIMEOUT  = 15 * time.Second
)

type SshOption struct {
	BasicOption
	Name                 string   `proxy:"name"`
	Server               string   `proxy:"server"`
	Port                 int      `proxy:"port"`
	UserName             string   `proxy:"username"`
	Password             string   `proxy:"password,omitempty"`
	PrivateKey           string   `proxy:"private-key,omitempty"`
	PrivateKeyPassphrase string   `proxy:"private-key-passphrase,omitempty"`
	HostKey              []string `proxy:"host-key,omitempty"`
	HostKeyAlgorithms    []string `proxy:"host-key-algorithms,omitempty"`
}

func (s *Ssh) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	client, err := s.connect(ctx, s.addr)
	if err != nil {
		return nil, err
	}
	c, err := client.DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		s.kickKeepAlive(client)
		return nil, err
	}

	return NewConn(c, s), nil
}

func (s *Ssh) connect(ctx context.Context, addr string) (client *ssh.Client, err error) {
	s.cMutex.Lock()
	defer s.cMutex.Unlock()
	if s.client != nil {
		return s.client, nil
	}
	c, err := s.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	// Force the SSH transport to shut down when the underlying connection write
	// fails. handshakeTransport caches this error without closing the transport,
	// which can leave the shared client permanently unusable while Wait remains
	// blocked. Closing the connection lets the read and mux loops exit so the
	// cached client can be discarded and replaced.
	c = closeOnWriteErrorConn{Conn: c, name: s.Name(), addr: addr}

	clientConn, chans, reqs, err := ssh.NewClientConn(c, addr, s.config)
	if err != nil {
		return nil, err
	}
	client = ssh.NewClient(clientConn, chans, reqs)

	s.client = client
	kick := make(chan struct{}, 1)
	s.kick = kick
	done := make(chan struct{})
	go s.keepAlive(client, addr, kick, done)

	go func() {
		err := client.Wait() // wait shutdown
		log.Warnln("[SSH] %s transport to %s ended: %v (%T)", s.Name(), addr, err, err)
		close(done)
		_ = client.Close()
		s.cMutex.Lock()
		defer s.cMutex.Unlock()
		if s.client == client {
			s.client = nil
		}
	}()

	return client, nil
}

// kickKeepAlive 在开 channel 失败后请求对 client 立即做一次心跳探测。
func (s *Ssh) kickKeepAlive(client *ssh.Client) {
	s.cMutex.Lock()
	defer s.cMutex.Unlock()
	if s.client != client {
		return
	}
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func (s *Ssh) keepAlive(client *ssh.Client, addr string, kick <-chan struct{}, done <-chan struct{}) {
	ticker := time.NewTicker(SSH_KEEPALIVE_INTERVAL)
	defer ticker.Stop()
	for {
		kicked := false
		select {
		case <-done:
			return
		case <-ticker.C:
		case <-kick:
			kicked = true
			log.Warnln("[SSH] %s channel open failed, probing transport to %s", s.Name(), addr)
		}
		start := time.Now()
		reply := make(chan error, 1)
		go func() {
			// OpenSSH 对未知的 keepalive@openssh.com 回 REQUEST_FAILURE，收到任何回复即视为存活
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			reply <- err
		}()
		timer := time.NewTimer(SSH_KEEPALIVE_TIMEOUT)
		select {
		case err := <-reply:
			timer.Stop()
			if err != nil {
				log.Warnln("[SSH] %s keepalive to %s failed: %v", s.Name(), addr, err)
				return
			}
			if kicked {
				log.Warnln("[SSH] %s keepalive to %s ok in %s after channel open failure, keeping transport", s.Name(), addr, time.Since(start))
			}
		case <-timer.C:
			log.Warnln("[SSH] %s keepalive to %s got no reply in %s, closing transport", s.Name(), addr, SSH_KEEPALIVE_TIMEOUT)
			_ = client.Close()
			return
		case <-done:
			timer.Stop()
			return
		}
	}
}

type closeOnWriteErrorConn struct {
	net.Conn
	name string
	addr string
}

func (c closeOnWriteErrorConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		var errno syscall.Errno
		errors.As(err, &errno)
		log.Warnln("[SSH] %s underlying write to %s failed: %v (errno %d)", c.name, c.addr, err, errno)
		_ = c.Conn.Close()
	}
	return n, err
}

// ProxyInfo implements C.ProxyAdapter
func (s *Ssh) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (s *Ssh) Close() error {
	s.cMutex.Lock()
	defer s.cMutex.Unlock()
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

func NewSsh(option SshOption) (*Ssh, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	config := ssh.ClientConfig{
		User:              option.UserName,
		HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
		HostKeyAlgorithms: option.HostKeyAlgorithms,
	}

	if option.PrivateKey != "" {
		var b []byte
		var err error
		if strings.Contains(option.PrivateKey, "PRIVATE KEY") {
			b = []byte(option.PrivateKey)
		} else {
			path := C.Path.Resolve(option.PrivateKey)
			if !C.Path.IsSafePath(path) {
				return nil, C.Path.ErrNotSafePath(path)
			}
			b, err = os.ReadFile(path)
			if err != nil {
				return nil, err
			}
		}
		var pKey ssh.Signer
		if option.PrivateKeyPassphrase != "" {
			pKey, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(option.PrivateKeyPassphrase))
		} else {
			pKey, err = ssh.ParsePrivateKey(b)
		}
		if err != nil {
			return nil, err
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(pKey))
	}

	if option.Password != "" {
		config.Auth = append(config.Auth, ssh.Password(option.Password))
	}

	if len(option.HostKey) != 0 {
		keys := make([]ssh.PublicKey, len(option.HostKey))
		for i, hostKey := range option.HostKey {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey))
			if err != nil {
				return nil, fmt.Errorf("parse host key :%s", key)
			}
			keys[i] = key
		}
		config.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			serverKey := key.Marshal()
			for _, hostKey := range keys {
				if bytes.Equal(serverKey, hostKey.Marshal()) {
					return nil
				}
			}
			return fmt.Errorf("host key mismatch, server send :%s %s", key.Type(), base64.StdEncoding.EncodeToString(serverKey))
		}
	}

	version := "SSH-2.0-OpenSSH_"
	if randv2.IntN(2) == 0 {
		version += "7." + strconv.Itoa(randv2.IntN(10))
	} else {
		version += "8." + strconv.Itoa(randv2.IntN(9))
	}
	config.ClientVersion = version

	outbound := &Ssh{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Ssh,
			ProviderName: option.ProviderName,
			UDP:          false,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
		config: &config,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
