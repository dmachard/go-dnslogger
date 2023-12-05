package loggers

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/dmachard/go-dnscollector/dnsutils"
	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-logger"
)

func Test_InfluxDB(t *testing.T) {
	// init logger
	g := NewInfluxDBClient(pkgconfig.GetFakeConfig(), logger.New(false), "test")

	// fake msgpack receiver
	fakeRcvr, err := net.Listen(pkgconfig.SocketTCP, "127.0.0.1:8086")
	if err != nil {
		t.Fatal(err)
	}
	defer fakeRcvr.Close()

	// start the logger
	go g.Run()

	// send fake dns message to logger
	dm := dnsutils.GetFakeDNSMessage()
	g.Channel() <- dm

	// accept conn
	conn, err := fakeRcvr.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// read data on fake server side

	// read and parse http request on server side
	request, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte(pkgconfig.HTTPOK))

	payload, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}

	if len(payload) == 0 {
		t.Errorf("error to read data: %s", err)
	}
}
