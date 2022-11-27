package collectors

import (
	"bufio"
	"crypto/tls"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-framestream"
	"github.com/dmachard/go-logger"
)

type DnstapRelay struct {
	done     chan bool
	listen   net.Listener
	conns    []net.Conn
	sockPath string
	loggers  []dnsutils.Worker
	config   *dnsutils.Config
	logger   *logger.Logger
	name     string
}

func NewDnstapRelay(loggers []dnsutils.Worker, config *dnsutils.Config, logger *logger.Logger, name string) *DnstapRelay {
	logger.Info("[%s] dnstap relay collector - enabled", name)
	s := &DnstapRelay{
		done:    make(chan bool),
		config:  config,
		loggers: loggers,
		logger:  logger,
		name:    name,
	}
	s.ReadConfig()
	return s
}

func (c *DnstapRelay) GetName() string { return c.name }

func (c *DnstapRelay) SetLoggers(loggers []dnsutils.Worker) {
	c.loggers = loggers
}

func (c *DnstapRelay) Loggers() []chan dnsutils.DnsMessage {
	channels := []chan dnsutils.DnsMessage{}
	for _, p := range c.loggers {
		channels = append(channels, p.Channel())
	}
	return channels
}

func (c *DnstapRelay) ReadConfig() {
	if !dnsutils.IsValidTLS(c.config.Collectors.DnstapRelay.TlsMinVersion) {
		c.logger.Fatal("collector dnstap relay - invalid tls min version")
	}

	c.sockPath = c.config.Collectors.Dnstap.SockPath
}

func (c *DnstapRelay) LogInfo(msg string, v ...interface{}) {
	c.logger.Info("["+c.name+"] dnstap collector relay - "+msg, v...)
}

func (c *DnstapRelay) LogError(msg string, v ...interface{}) {
	c.logger.Error("["+c.name+"] dnstap collector relay - "+msg, v...)
}

func (c *DnstapRelay) HandleFrame(recvFrom chan []byte, sendTo []chan dnsutils.DnsMessage) {
	for data := range recvFrom {
		// init DNS message container
		dm := dnsutils.DnsMessage{}
		dm.Init()

		// register payload
		dm.DnsTap.Payload = data

		// forward to outputs
		for i := range sendTo {
			sendTo[i] <- dm
		}
	}
}

func (c *DnstapRelay) HandleConn(conn net.Conn) {
	// close connection on function exit
	defer conn.Close()

	// get peer address
	peer := conn.RemoteAddr().String()
	c.LogInfo("new connection from %s\n", peer)

	recvChan := make(chan []byte, 512)
	go c.HandleFrame(recvChan, c.Loggers())

	// frame stream library
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	fs := framestream.NewFstrm(r, w, conn, 5*time.Second, []byte("protobuf:dnstap.Dnstap"), true)

	// init framestream receiver
	if err := fs.InitReceiver(); err != nil {
		c.LogError("error stream receiver initialization: %s", err)
		return
	} else {
		c.LogInfo("receiver framestream initialized")
	}

	// process incoming frame and send it to recv channel
	if err := fs.ProcessFrame(recvChan); err != nil {
		c.LogError("transport error: %s", err)
	}

	close(recvChan)

	c.LogInfo("%s - connection closed\n", peer)
}

func (c *DnstapRelay) Channel() chan dnsutils.DnsMessage {
	return nil
}

func (c *DnstapRelay) Stop() {
	c.LogInfo("stopping...")

	// closing properly current connections if exists
	for _, conn := range c.conns {
		peer := conn.RemoteAddr().String()
		c.LogInfo("%s - closing connection...", peer)
		conn.Close()
	}
	// Finally close the listener to unblock accept
	c.LogInfo("stop listening...")
	c.listen.Close()

	// read done channel and block until run is terminated
	<-c.done
	close(c.done)
}

func (c *DnstapRelay) Listen() error {
	c.LogInfo("running in background...")

	var err error
	var listener net.Listener
	addrlisten := c.config.Collectors.Dnstap.ListenIP + ":" + strconv.Itoa(c.config.Collectors.Dnstap.ListenPort)

	if len(c.sockPath) > 0 {
		_ = os.Remove(c.sockPath)
	}

	// listening with tls enabled ?
	if c.config.Collectors.Dnstap.TlsSupport {
		c.LogInfo("tls support enabled")
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(c.config.Collectors.Dnstap.CertFile, c.config.Collectors.Dnstap.KeyFile)
		if err != nil {
			c.logger.Fatal("loading certificate failed:", err)
		}

		// prepare tls configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}

		// update tls min version according to the user config
		tlsConfig.MinVersion = dnsutils.TLS_VERSION[c.config.Collectors.Dnstap.TlsMinVersion]

		if len(c.sockPath) > 0 {
			listener, err = tls.Listen(dnsutils.SOCKET_UNIX, c.sockPath, tlsConfig)
		} else {
			listener, err = tls.Listen(dnsutils.SOCKET_TCP, addrlisten, tlsConfig)
		}
	} else {
		// basic listening
		if len(c.sockPath) > 0 {
			listener, err = net.Listen(dnsutils.SOCKET_UNIX, c.sockPath)
		} else {
			listener, err = net.Listen(dnsutils.SOCKET_TCP, addrlisten)
		}
	}

	// something is wrong ?
	if err != nil {
		return err
	}
	c.LogInfo("is listening on %s", listener.Addr())
	c.listen = listener
	return nil
}

func (c *DnstapRelay) Run() {
	c.LogInfo("starting collector...")
	if c.listen == nil {
		if err := c.Listen(); err != nil {
			c.logger.Fatal("collector dnstap listening failed: ", err)
		}
	}
	for {
		// Accept() blocks waiting for new connection.
		conn, err := c.listen.Accept()
		if err != nil {
			break
		}

		c.conns = append(c.conns, conn)
		go c.HandleConn(conn)
	}

	c.LogInfo("run terminated")
	c.done <- true
}
