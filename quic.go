package gost

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-log/log"
	quic "github.com/lucas-clemente/quic-go"
)

type quicSession struct {
	conn    net.Conn
	session quic.Session
}

func (session *quicSession) GetConn() (*quicConn, error) {
	fmt.Println("quic-1 GnetCoon")
	//stream, err := session.session.OpenStreamSync()
	stream, err := session.session.OpenStreamSync(context.Background())  //NEW
	if err != nil {
		return nil, err
	}
	return &quicConn{
		Stream: stream,
		laddr:  session.session.LocalAddr(),
		raddr:  session.session.RemoteAddr(),
	}, nil
}

func (session *quicSession) Close() error {
	fmt.Println("quic-2 Close")
	//return session.session.Close()
	return session.session.CloseWithError(201,"error test") //NEW
}

type quicTransporter struct {
	config       *QUICConfig
	sessionMutex sync.Mutex
	sessions     map[string]*quicSession
}

// QUICTransporter creates a Transporter that is used by QUIC proxy client.
func QUICTransporter(config *QUICConfig) Transporter {
	fmt.Println("quic-3 QUICTransporter")
	if config == nil {
		config = &QUICConfig{}
	}
	return &quicTransporter{
		config:   config,
		sessions: make(map[string]*quicSession),
	}
}

func (tr *quicTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	fmt.Println("-----------quic-4 Dial")
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	session, ok := tr.sessions[addr]
	if !ok {
		var cc *net.UDPConn
		cc, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return
		}
		conn = cc

		if tr.config != nil && tr.config.Key != nil {
			conn = &quicCipherConn{UDPConn: cc, key: tr.config.Key}
		}

		session = &quicSession{conn: conn}
		tr.sessions[addr] = session
	}
	return session.conn, nil
}

func (tr *quicTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	fmt.Println("quic-5 Handshake")
	opts := &HandshakeOptions{}  //opts是个新定义的HandshakeOptions结构体，注意带s与不带s的区别

	for _, option := range options {
		option(opts)
	}
	config := tr.config
	if opts.QUICConfig != nil {
		config = opts.QUICConfig
	}
	if config.TLSConfig == nil {
		// config.TLSConfig = &tls.Config{InsecureSkipVerify: true}
		config.TLSConfig = &tls.Config{                      //NEW
			InsecureSkipVerify: true,
			NextProtos:   []string{"HTTP"},
		}
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	session, ok := tr.sessions[opts.Addr]
	if session != nil && session.conn != conn {
		conn.Close()
		return nil, errors.New("quic: unrecognized connection")
	}
	if !ok || session.session == nil {
		s, err := tr.initSession(opts.Addr, conn, config)
		if err != nil {
			conn.Close()
			delete(tr.sessions, opts.Addr)
			return nil, err
		}
		session = s
		tr.sessions[opts.Addr] = session
	}
	cc, err := session.GetConn()
	if err != nil {
		session.Close()
		delete(tr.sessions, opts.Addr)
		return nil, err
	}

	return cc, nil
}

func (tr *quicTransporter) initSession(addr string, conn net.Conn, config *QUICConfig) (*quicSession, error) {
	fmt.Println("quic-6 initSession")
	udpConn, ok := conn.(net.PacketConn)
	if !ok {
		return nil, errors.New("quic: wrong connection type")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	quicConfig := &quic.Config{
		//HandshakeTimeout: config.Timeout,
		HandshakeIdleTimeout: config.Timeout,         //NEW
		KeepAlive:        config.KeepAlive,
		//IdleTimeout:      config.IdleTimeout,
		MaxIdleTimeout:      config.IdleTimeout,       //NEW
		Versions: []quic.VersionNumber{   //NEW
			//quic.VersionGQUIC43,
			//quic.VersionGQUIC39,
			quic.VersionDraft29,
			quic.VersionDraft32,
			quic.VersionDraft34,
		},
	}


		config.TLSConfig = &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:   []string{"HTTP"},  //NEW
		}

	session, err := quic.Dial(udpConn, udpAddr, addr, config.TLSConfig, quicConfig)
	if err != nil {
		log.Logf("quic dial %s: %v", addr, err)
		return nil, err
	}
	return &quicSession{conn: conn, session: session}, nil
}

func (tr *quicTransporter) Multiplex() bool {
	fmt.Println("quic-7 Multiplex")
	return true
}

// QUICConfig is the config for QUIC client and server
type QUICConfig struct {
	TLSConfig   *tls.Config
	Timeout     time.Duration
	KeepAlive   bool
	IdleTimeout time.Duration
	Key         []byte
}

type quicListener struct {
	ln       quic.Listener
	connChan chan net.Conn
	errChan  chan error
}

// QUICListener creates a Listener for QUIC proxy server.
func QUICListener(addr string, config *QUICConfig) (Listener, error) {
	fmt.Println("quic-8")
	if config == nil {
		config = &QUICConfig{}
	}
	quicConfig := &quic.Config{
		//HandshakeTimeout: config.Timeout,
		HandshakeIdleTimeout: config.Timeout,
		KeepAlive:        config.KeepAlive,
		//IdleTimeout:      config.IdleTimeout,
		MaxIdleTimeout:      config.IdleTimeout,
	}

	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = DefaultTLSConfig
	}
	var conn net.PacketConn

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	lconn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	conn = lconn

	if config.Key != nil {
		conn = &quicCipherConn{UDPConn: lconn, key: config.Key}
	}

	tlsConfig.NextProtos = []string{"HTTP"}   //NEW

	ln, err := quic.Listen(conn, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}

	l := &quicListener{
		ln:       ln,
		connChan: make(chan net.Conn, 1024),
		errChan:  make(chan error, 1),
	}
	go l.listenLoop()

	return l, nil
}

func (l *quicListener) listenLoop() {
	fmt.Println("quic-8 ListenLoop")
	for {
		//session, err := l.ln.Accept()
		session, err := l.ln.Accept(context.Background())  //NEW
		if err != nil {
			log.Log("[quic] accept:", err)
			l.errChan <- err
			close(l.errChan)
			return
		}
		go l.sessionLoop(session)
	}
}

func (l *quicListener) sessionLoop(session quic.Session) {
	fmt.Println("quic-9 SessionLoop")
	log.Logf("[quic] %s <-> %s", session.RemoteAddr(), session.LocalAddr())
	defer log.Logf("[quic] %s >-< %s", session.RemoteAddr(), session.LocalAddr())

	for {
		//stream, err := session.AcceptStream()
		stream, err := session.AcceptStream(context.Background()) //NEW
		if err != nil {
			log.Log("[quic] accept stream:", err)
			//session.Close()
			session.CloseWithError(201,"test err")
			return
		}

		cc := &quicConn{Stream: stream, laddr: session.LocalAddr(), raddr: session.RemoteAddr()}
		select {
		case l.connChan <- cc:
		default:
			cc.Close()
			log.Logf("[quic] %s - %s: connection queue is full", session.RemoteAddr(), session.LocalAddr())
		}
	}
}

func (l *quicListener) Accept() (conn net.Conn, err error) {
	fmt.Println("quic-10 Accept")
	var ok bool
	select {
	case conn = <-l.connChan:
	case err, ok = <-l.errChan:
		if !ok {
			err = errors.New("accpet on closed listener")
		}
	}
	return
}

func (l *quicListener) Addr() net.Addr {
	fmt.Println("quic-11 Addr")
	return l.ln.Addr()
}

func (l *quicListener) Close() error {
	fmt.Println("quic-12 Close")
	return l.ln.Close()
}

type quicConn struct {
	quic.Stream
	laddr net.Addr
	raddr net.Addr
}

func (c *quicConn) LocalAddr() net.Addr {
	fmt.Println("quic-13 LocalAddr")
	return c.laddr
}

func (c *quicConn) RemoteAddr() net.Addr {
	fmt.Println("quic-14 RemoteAddr")
	return c.raddr
}

type quicCipherConn struct {
	*net.UDPConn
	key []byte
}

func (conn *quicCipherConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	fmt.Println("quic-15 ReadFrom")
	n, addr, err = conn.UDPConn.ReadFrom(data)
	if err != nil {
		return
	}
	b, err := conn.decrypt(data[:n])
	if err != nil {
		return
	}

	copy(data, b)

	return len(b), addr, nil
}

func (conn *quicCipherConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	fmt.Println("quic-16 Writeto")
	b, err := conn.encrypt(data)
	if err != nil {
		return
	}

	_, err = conn.UDPConn.WriteTo(b, addr)
	if err != nil {
		return
	}

	return len(b), nil
}

func (conn *quicCipherConn) encrypt(data []byte) ([]byte, error) {
	fmt.Println("quic-17 encrypt")
	c, err := aes.NewCipher(conn.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (conn *quicCipherConn) decrypt(data []byte) ([]byte, error) {
	fmt.Println("quic-18 decrypt")
	c, err := aes.NewCipher(conn.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
