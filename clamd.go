package goclamd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"time"
)

// EICAR example virus
var EICAR = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)

const (
	// ResOK resolution OK
	ResOK = "OK"
	// ResFound resolution virus found
	ResFound = "FOUND"
	// ResError resolution scan error
	ResError = "ERROR"
	// ResParseError resolution parse error
	ResParseError = "PARSE ERROR"
)

// StreamScanner can be used to stream a file to clamd
type StreamScanner interface {
	Scan(io.Reader) error
	Ping() error
	Reload() error
}

type streamScanner struct {
	endpoint string
}

func (s *streamScanner) Scan(r io.Reader) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := DialContext(ctx, s.endpoint)
	if err != nil {
		return err
	}

	defer c.Close()

	err = c.Command("INSTREAM")
	if err != nil {
		return err
	}

	// MAX FILESIZE IS 26213574
	//Using io.Copy default buffer which is 32 * 1024
	_, err = io.Copy(c, r)
	if err != nil {
		return CheckResponse(c.ReadResponse())
	}

	// Empty chunk tells clamd we are done streaming. We can now read the result
	_, err = c.Write([]byte{})
	if err != nil {
		return err
	}

	return CheckResponse(c.ReadResponse())
}

// Ping pings clamd and returns error if no pong is recieved
func (s *streamScanner) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := DialContext(ctx, s.endpoint)
	if err != nil {
		return err
	}
	defer c.Close()

	err = c.SetDeadline(time.Now().Add(time.Second * 2))
	if err != nil {
		return err
	}

	err = c.Command("PING")
	if err != nil {
		return err
	}
	pong, err := c.ReadResponse()

	if string(pong) != "PONG" {
		return fmt.Errorf("goclamd: expected PONG, got: %s", string(pong))
	}
	return err
}

// Reload the virus databases
func (s *streamScanner) Reload() error {
        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
        defer cancel()
        c, err := DialContext(ctx, s.endpoint)
        if err != nil {
                return err
        }
        defer c.Close()

        err = c.SetDeadline(time.Now().Add(time.Second * 2))
        if err != nil {
                return err
        }

        err = c.Command("RELOAD")
        if err != nil {
                return err
        }
        reload, err := c.ReadResponse()

        if string(reload) != "RELOADING" {
                return fmt.Errorf("goclamd: expected RELOADING, got: %s", string(reload))
        }
        return err
}

var statusRegexp = regexp.MustCompile(`^(.*): (.*) (FOUND|ERROR|OK)`)

//CheckResponse checks a clamd response for OK or virus found
func CheckResponse(r []byte, err error) error {
	if err != nil {
		return err
	}

	if bytes.Equal(r, []byte("stream: OK")) {
		return nil
	}

	match := statusRegexp.FindSubmatch(r)
	if len(match) > 3 {
		return NewVirusFoundError(match[3], match[2])
	}
	return fmt.Errorf(string(r))
}

// NewStreamScanner returns a new scanner which uses clamd stream functionality
func NewStreamScanner(endpoint string) StreamScanner {
	return &streamScanner{
		endpoint: endpoint,
	}
}
