package udpmux

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var _ net.PacketConn = dummyPacketConn{}

type dummyPacketConn struct{}

// Close implements net.PacketConn
func (dummyPacketConn) Close() error {
	return nil
}

// LocalAddr implements net.PacketConn
func (dummyPacketConn) LocalAddr() net.Addr {
	return nil
}

// ReadFrom implements net.PacketConn
func (dummyPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, &net.UDPAddr{}, nil
}

// SetDeadline implements net.PacketConn
func (dummyPacketConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implements net.PacketConn
func (dummyPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements net.PacketConn
func (dummyPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// WriteTo implements net.PacketConn
func (dummyPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return 0, nil
}

func hasConn(m *udpMux, ufrag string, isIPv6 bool) *muxedConnection {
	key := ufragConnKey{ufrag, isIPv6}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ufragMap[key]
}

func TestUDPMux_GetConn(t *testing.T) {
	mux := NewUDPMux(dummyPacketConn{}, nil)
	m := mux.(*udpMux)
	require.Nil(t, hasConn(m, "test", false))
	conn, err := mux.GetConn("test", false)
	require.NoError(t, err)
	require.NotNil(t, conn)

	require.Nil(t, hasConn(m, "test", true))
	connv6, err := mux.GetConn("test", true)
	require.NoError(t, err)
	require.NotNil(t, connv6)

	require.NotEqual(t, conn, connv6)
}

func TestUDPMux_RemoveConnectionOnClose(t *testing.T) {
	mux := NewUDPMux(dummyPacketConn{}, nil)
	conn, err := mux.GetConn("test", false)
	require.NoError(t, err)
	require.NotNil(t, conn)

	m := mux.(*udpMux)
	require.NotNil(t, hasConn(m, "test", false))

	err = conn.Close()
	require.NoError(t, err)

	require.Nil(t, hasConn(m, "test", false))
}
