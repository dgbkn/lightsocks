package server

import (
	"encoding/binary"
	"net"

	"github.com/gwuhaolin/lightsocks"
)

type LsServer struct {
	Cipher     *lightsocks.Cipher
	ListenAddr *net.TCPAddr
}

// Create a service terminal
// Responsibilities of service end:
// 1. Monitor requests from local client clients
// 2. Decrypt local proxy client request data, analyze SOCKS5 protocol, connect user browser to the remote server that actually wants to connect
// 3. Transferring the browser to the actual desired connection to the remote server and returning the encrypted content to the local server client.

func NewLsServer(password string, listenAddr string) (*LsServer, error) {
	bsPassword, err := lightsocks.ParsePassword(password)
	if err != nil {
		return nil, err
	}
	structListenAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &LsServer{
		Cipher:     lightsocks.NewCipher(bsPassword),
		ListenAddr: structListenAddr,
	}, nil

}

// Run service server and monitor requests from local proxy clients
func (lsServer *LsServer) Listen(didListen func(listenAddr *net.TCPAddr)) error {
	return lightsocks.ListenEncryptedTCP(lsServer.ListenAddr, lsServer.Cipher, lsServer.handleConn, didListen)
}

// understanding SOCKS5 protocol
// https://www.ietf.org/rfc/rfc1928.txt
func (lsServer *LsServer) handleConn(localConn *lightsocks.SecureTCPConn) {
	defer localConn.Close()
	buf := make([]byte, 256)

	/**
	   The localConn connects to the dstServer, and sends a ver
	   identifier/method selection message:
		          +----+----------+----------+
		          |VER | NMETHODS | METHODS  |
		          +----+----------+----------+
		          | 1  |    1     | 1 to 255 |
		          +----+----------+----------+
	   The VER field is set to X'05' for this ver of the protocol.  The
	   NMETHODS field contains the number of method identifier octets that
	   appear in the METHODS field.
	*/
	// The first field VER represents the version of Socks, Socks5 defaults to 0x05, and the fixed length is 1 byte.
	_, err := localConn.DecodeRead(buf)
	// only support version 5
	if err != nil || buf[0] != 0x05 {
		return
	}

	/**
	   The dstServer selects from one of the methods given in METHODS, and
	   sends a METHOD selection message:

		          +----+--------+
		          |VER | METHOD |
		          +----+--------+
		          | 1  |   1    |
		          +----+--------+
	*/
	// No verification, direct verification
	localConn.EncodeWrite([]byte{0x05, 0x00})

	/**
	  +----+-----+-------+------+----------+----------+
	  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	  +----+-----+-------+------+----------+----------+
	  | 1  |  1  | X'00' |  1   | Variable |    2     |
	  +----+-----+-------+------+----------+----------+
	*/

	// Get real remote service address
	n, err := localConn.DecodeRead(buf)
	// The shortest length is 7 and the condition is ATYP=3 DST.ADDR occupies 1 byte value of 0x0.
	if err != nil || n < 7 {
		return
	}

	// CMD represents the type of client request, the value length is also 1 byte, there are three types.
	// CONNECT X'01'
	if buf[1] != 0x01 {
		// currently only support CONNECT
		return
	}

	var dIP []byte
	// aType represents the remote server address type of the request, value length is 1 byte, and has three types.	switch buf[3] {
	case 0x01:
		//	IP V4 address: X'01'
		dIP = buf[4 : 4+net.IPv4len]
	case 0x03:
		//	DOMAINNAME: X'03'
		ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:n-2]))
		if err != nil {
			return
		}
		dIP = ipAddr.IP
	case 0x04:
		//	IP V6 address: X'04'
		dIP = buf[4 : 4+net.IPv6len]
	default:
		return
	}
	dPort := buf[n-2:]
	dstAddr := &net.TCPAddr{
		IP:   dIP,
		Port: int(binary.BigEndian.Uint16(dPort)),
	}

	// connect real remote service
	dstServer, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		return
	} else {
		defer dstServer.Close()
		// Directly clears all data when Conn is closed, regardless of not sent data
		dstServer.SetLinger(0)

		// response client connection successful
		/**
		  +----+-----+-------+------+----------+----------+
		  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		  +----+-----+-------+------+----------+----------+
		  | 1  |  1  | X'00' |  1   | Variable |    2     |
		  +----+-----+-------+------+----------+----------+
		*/
		// response client connection successful
		localConn.EncodeWrite([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}

//transition
// Read data from localUser and send to dstServer
	go func() {
		err := localConn.DecodeCopy(dstServer)
		if err != nil {
			// Errors such as network overtime may exist during the copy process and are returned, as soon as an error occurs, this job is exited.
			localConn.Close()
			dstServer.Close()
		}
	}()
	// Read data from dstServer and send it to localUser, because the probability of network error occurring at the translation wall stage is higher here.
	(&lightsocks.SecureTCPConn{
		Cipher:          localConn.Cipher,
		ReadWriteCloser: dstServer,
	}).EncodeCopy(localConn)
}
