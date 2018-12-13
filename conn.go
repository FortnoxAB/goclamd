package goclamd

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
)

// Conn is a clamd stream compliant Connection that can use Write to stream chunks
type Conn interface {
	net.Conn
	Command(cmd string) error
	ReadResponse() ([]byte, error)
}

type conn struct {
	net.Conn
}

func (c *conn) Command(cmd string) error {
	_, err := c.Conn.Write([]byte(fmt.Sprintf("n%s\n", cmd)))
	return err
}

//Write implements io.Writer and is made so we can use io.Copy to copy using a buffer to comply with clamd chunks
func (c *conn) Write(p []byte) (int, error) {
	err := binary.Write(c.Conn, binary.BigEndian, uint32(len(p)))
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}
func (c *conn) ReadResponse() ([]byte, error) {
	buf := &bytes.Buffer{}
	_, err := buf.ReadFrom(c)
	return bytes.TrimSpace(buf.Bytes()), err
}

// DialContext dials and takes a context for cancellation
func DialContext(ctx context.Context, endpoint string) (Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", endpoint)
	return &conn{c}, err
}
