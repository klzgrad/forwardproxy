package forwardproxy

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"go.uber.org/zap"
)

func TestDatagram(t *testing.T) {
	t.Run("test datagram with byte payload", func(t *testing.T) {
		tests := []Datagram{
			{
				Type:   0,
				Length: 4,
				Payload: &BytePayload{
					Payload: []byte("1234"),
				},
			},
			{
				Type:   0,
				Length: 8,
				Payload: &BytePayload{
					Payload: []byte("12345678"),
				},
			},
		}

		for _, v := range tests {
			buffer := &bytes.Buffer{}
			if err := v.Send(buffer); err != nil {
				t.Errorf("send datagram error: %v", err)
			}

			vv := Datagram{}
			if err := vv.Receive(buffer); err != nil {
				t.Errorf("receive datagram error: %v", err)
			}

			if v.Type != vv.Type || v.Length != vv.Length {
				t.Errorf("want %v, %v, get %v, %v", v.Type, v.Length, vv.Type, vv.Length)
			}

			if !bytes.Equal((v.Payload.(*BytePayload)).Payload, (vv.Payload.(*BytePayload)).Payload) {
				t.Errorf("want %v, get %v", (v.Payload.(*BytePayload)).Payload, (vv.Payload.(*BytePayload)).Payload)
			}
		}
	})
}

func TestCompressedPayload(t *testing.T) {
	t.Run("test datagram with compression payload", func(t *testing.T) {
		tests := []Datagram{
			{
				Type:   0,
				Length: uint64(quicvarint.Len(2)) + 10,
				Payload: &CompressedPayload{
					ContextID: 2,
					Payload:   []byte("1234567890"),
				},
			},
			{
				Type:   0,
				Length: uint64(quicvarint.Len(99999)) + 10,
				Payload: &CompressedPayload{
					ContextID: 99999,
					Payload:   []byte("1234567890"),
				},
			},
		}

		for _, v := range tests {
			buffer := &bytes.Buffer{}
			if err := v.Send(buffer); err != nil {
				t.Errorf("send datagram error: %v", err)
			}

			vv := Datagram{}
			if err := vv.Receive(buffer); err != nil {
				t.Errorf("receive datagram error: %v", err)
			}

			if v.Type != vv.Type || v.Length != vv.Length {
				t.Errorf("want %v, %v, get %v, %v", v.Type, v.Length, vv.Type, vv.Length)
			}

			pl := &CompressedPayload{}
			if err := pl.Parse(vv.Payload.(*BytePayload).Payload); err != nil {
				t.Errorf("parse payload error: %v", err)
			}

			if tt := v.Payload.(*CompressedPayload); tt.ContextID == pl.ContextID {
				if !bytes.Equal(tt.Payload, pl.Payload) {
					t.Errorf("payload want %v, get %v", tt.Payload, pl.Payload)
				}
			} else {
				t.Errorf("context id want %v, get %v", tt.ContextID, pl.ContextID)
			}
		}
	})
}

func TestUncompressedPayload(t *testing.T) {
	t.Run("test datagram with uncompression payload", func(t *testing.T) {
		tests := []Datagram{
			{
				Type:   2,
				Length: uint64(quicvarint.Len(99999)) + 1 + 4 + 2 + 10,
				Payload: &UncompressedPayload{
					ContextID: 99999,
					IPVersion: 4,
					Addr:      netip.AddrFrom4([4]byte{1, 2, 3, 4}),
					Port:      80,
					Payload:   []byte("1234567890"),
				},
			},
			{
				Type:   2,
				Length: uint64(quicvarint.Len(8080)) + 1 + 16 + 2 + 10,
				Payload: &UncompressedPayload{
					ContextID: 8080,
					IPVersion: 6,
					Addr:      netip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
					Port:      443,
					Payload:   []byte("1234567890"),
				},
			},
		}

		for _, v := range tests {
			buffer := &bytes.Buffer{}
			if err := v.Send(buffer); err != nil {
				t.Errorf("send datagram error: %v", err)
			}

			vv := Datagram{}
			if err := vv.Receive(buffer); err != nil {
				t.Errorf("receive datagram error: %v", err)
			}

			if v.Type != vv.Type || v.Length != vv.Length {
				t.Errorf("want %v, %v, get %v, %v", v.Type, v.Length, vv.Type, vv.Length)
			}

			pl := &UncompressedPayload{}
			if err := pl.Parse(vv.Payload.(*BytePayload).Payload); err != nil {
				t.Errorf("parse payload error: %v", err)
			}

			if tt := v.Payload.(*UncompressedPayload); tt.ContextID == pl.ContextID {
				if pl.IPVersion != tt.IPVersion {
					t.Errorf("IP version want %v, get %v", tt.IPVersion, pl.IPVersion)
				}
				if pl.Addr != tt.Addr {
					t.Errorf("addr want %v, get %v", tt.Addr, pl.Addr)
				}
				if pl.Port != tt.Port {
					t.Errorf("port want %v, get %v", tt.Port, pl.Port)
				}
				if !bytes.Equal(tt.Payload, pl.Payload) {
					t.Errorf("payload want %v, get %v", tt.Payload, pl.Payload)
				}
			} else {
				t.Errorf("context id want %v, get %v", tt.ContextID, pl.ContextID)
			}
		}
	})
}

func TestCompressionAssign(t *testing.T) {
	t.Run("test datagram with compression assign payload", func(t *testing.T) {
		tests := []Datagram{
			{
				Type:   CompressionAssignValue,
				Length: uint64(quicvarint.Len(2)) + 1,
				Payload: &CompressionAssignPayload{
					ContextID: 2,
					IPVersion: 0,
				},
			},
			{
				Type:   CompressionAssignValue,
				Length: uint64(quicvarint.Len(99999)) + 1 + 4 + 2,
				Payload: &CompressionAssignPayload{
					ContextID: 99999,
					IPVersion: 4,
					Addr:      netip.AddrFrom4([4]byte{1, 2, 3, 4}),
					Port:      80,
				},
			},
			{
				Type:   CompressionAssignValue,
				Length: uint64(quicvarint.Len(8080)) + 1 + 16 + 2,
				Payload: &CompressionAssignPayload{
					ContextID: 8080,
					IPVersion: 6,
					Addr:      netip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
					Port:      443,
				},
			},
		}

		for _, v := range tests {
			buffer := &bytes.Buffer{}
			if err := v.Send(buffer); err != nil {
				t.Errorf("send datagram error: %v", err)
			}

			vv := Datagram{}
			if err := vv.Receive(buffer); err != nil {
				t.Errorf("receive datagram error: %v", err)
			}

			if v.Type != vv.Type || v.Length != vv.Length {
				t.Errorf("want %v, %v, get %v, %v", v.Type, v.Length, vv.Type, vv.Length)
			}

			pl := &CompressionAssignPayload{}
			if err := pl.Parse(vv.Payload.(*BytePayload).Payload); err != nil {
				t.Errorf("parse payload error: %v", err)
			}

			if tt := v.Payload.(*CompressionAssignPayload); tt.ContextID == pl.ContextID {
				if pl.IPVersion != tt.IPVersion {
					t.Errorf("IP version want %v, get %v", tt.IPVersion, pl.IPVersion)
				}
				if pl.Addr != tt.Addr {
					t.Errorf("addr want %v, get %v", tt.Addr, pl.Addr)
				}
				if pl.Port != tt.Port {
					t.Errorf("port want %v, get %v", tt.Port, pl.Port)
				}
			} else {
				t.Errorf("context id want %v, get %v", tt.ContextID, pl.ContextID)
			}
		}
	})
}

func TestCompressionClose(t *testing.T) {
	t.Run("test datagram with compression close payload", func(t *testing.T) {
		tests := []Datagram{
			{
				Type:   CompressionCloseValue,
				Length: uint64(quicvarint.Len(2)),
				Payload: &CompressionClosePayload{
					ContextID: 2,
				},
			},
			{
				Type:   CompressionCloseValue,
				Length: uint64(quicvarint.Len(99999)),
				Payload: &CompressionClosePayload{
					ContextID: 99999,
				},
			},
		}

		for _, v := range tests {
			buffer := &bytes.Buffer{}
			if err := v.Send(buffer); err != nil {
				t.Errorf("send datagram error: %v", err)
			}

			vv := Datagram{}
			if err := vv.Receive(buffer); err != nil {
				t.Errorf("receive datagram error: %v", err)
			}

			if v.Type != vv.Type || v.Length != vv.Length {
				t.Errorf("want %v, %v, get %v, %v", v.Type, v.Length, vv.Type, vv.Length)
			}

			pl := &CompressionClosePayload{}
			if err := pl.Parse(vv.Payload.(*BytePayload).Payload); err != nil {
				t.Errorf("parse payload error: %v", err)
			}

			if tt := v.Payload.(*CompressionClosePayload); tt.ContextID != pl.ContextID {
				t.Errorf("context id want %v, get %v", tt.ContextID, pl.ContextID)
			}
		}
	})
}

func TestNatMap(t *testing.T) {
	tests := []struct {
		Database []struct {
			ContextID uint64
			Addr      netip.AddrPort
		}
		TestSet []struct {
			ContextID uint64
			Addr      netip.AddrPort
		}
	}{
		{
			Database: []struct {
				ContextID uint64
				Addr      netip.AddrPort
			}{
				{
					ContextID: 4,
					Addr:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 80),
				},
				{
					ContextID: 6,
					Addr:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 5}), 80),
				},
				{
					ContextID: 8,
					Addr:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 7}), 80),
				},
			},
			TestSet: []struct {
				ContextID uint64
				Addr      netip.AddrPort
			}{
				{
					ContextID: 4,
					Addr:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 80),
				},
			},
		},
		{
			Database: []struct {
				ContextID uint64
				Addr      netip.AddrPort
			}{
				{
					ContextID: 4,
					Addr:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 6}), 80),
				},
				{
					ContextID: 7,
					Addr:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 11}), 80),
				},
				{
					ContextID: 9,
					Addr:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 13}), 80),
				},
			},
			TestSet: []struct {
				ContextID uint64
				Addr      netip.AddrPort
			}{
				{
					ContextID: 4,
					Addr:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 6}), 80),
				},
			},
		},
	}

	t.Run("test nat map", func(t *testing.T) {
		for _, v := range tests {
			database := v.Database
			testset := v.TestSet

			nm := newPacketConn(nil)

			for _, vv := range database {
				nm.Add(vv.ContextID, vv.Addr)
			}

			for _, vv := range testset {
				id, ok := nm.GetContextID(vv.Addr)
				if ok {
					if id != vv.ContextID {
						t.Errorf("for addr: %v, want: %v, get: %v", vv.Addr, vv.ContextID, id)
					}
				} else {
					t.Errorf("for addr: %v no valid id", vv.Addr)
				}
				addr, ok := nm.GetAddr(vv.ContextID)
				if ok {
					if addr != vv.Addr {
						t.Errorf("for id: %v, want: %v, get: %v", vv.ContextID, vv.Addr, addr)
					}
				} else {
					t.Errorf("for id: %v no valid addr", vv.ContextID)
				}
			}
		}
	})
}

func TestExtract(t *testing.T) {
	t.Run("test udp uri", func(t *testing.T) {
		tests := []struct {
			Template string
			Tests    []string
			Extract  []string
			Target   [][]string
		}{
			{
				Template: "https://{host}/.well-known/masque/udp/{target_host}/{target_port}/",
				Tests: []string{
					"https://example.com/.well-known/masque/udp/1.2.3.4/1234/",
					"https://example.com/.well-known/masque/udp/1.2.3.4/1235/",
					"https://example.com/.well-known/masque/udp/example.com/1111/",
				},
				Extract: []string{"target_host", "target_port"},
				Target: [][]string{
					{
						"1.2.3.4",
						"1234",
					},
					{
						"1.2.3.4",
						"1235",
					},
					{
						"example.com",
						"1111",
					},
				},
			},
			{
				Template: "/{year}/{month}/{day}/{title}.html",
				Tests: []string{
					"/2012/08/12/test.html",
				},
				Extract: []string{"year", "month", "day"},
				Target: [][]string{
					{
						"2012",
						"08",
						"12",
					},
				},
			},
		}

		for _, v := range tests {
			rm := RequestMatcher{}
			rm.Create(v.Template)

			for i, vv := range v.Tests {
				match, _ := rm.Extract(vv)
				for j, m := range v.Extract {
					if v.Target[i][j] != match[m] {
						t.Errorf("extract: %s, key: %s, want: %s, get: %s", vv, m, v.Target[i][j], match[m])
					}
				}
			}
		}
	})
}

func TestHandleStream(t *testing.T) {
	t.Run("test handle stream", func(t *testing.T) {
		srv, err := newUDPProxyServer("", zap.NewNop())
		if err != nil {
			t.Fatalf("create UDP proxy server error")
		}

		conn, rw := net.Pipe()
		defer conn.Close()
		defer rw.Close()

		// handle proxy
		go func() {
			rc, err := net.Dial("udp", "127.0.0.1:8899")
			if err != nil {
				t.Errorf("connect udp server error: %v", err)
			}
			defer rc.Close()

			if err := srv.HandleStream(conn, Request("127.0.0.1:8899"), rc.(*net.UDPConn)); err != nil {
				t.Errorf("handle stream error: %v", err)
			}
		}()

		// create udp server
		pkt, err := net.ListenPacket("udp", "127.0.0.1:8899")
		if err != nil {
			t.Fatalf("create udp server error: %v", err)
		}
		defer pkt.Close()

		// client send datagram
		hello := []byte("Hello world!")
		dg := Datagram{
			Type: 0,
		}
		pl := &CompressedPayload{
			ContextID: 0,
			Payload:   hello,
		}
		dg.Length = uint64(quicvarint.Len(0)) + uint64(len(pl.Payload))
		dg.Payload = pl

		// send payload to server
		if err := dg.Send(rw); err != nil {
			t.Errorf("send packet error: %v", err)
		}

		b := make([]byte, 2048)
		nr, addr, err := pkt.ReadFrom(b)
		if err != nil {
			t.Errorf("read packet conn error: %v", err)
		}

		if !bytes.Equal(b[:nr], pl.Payload) {
			t.Errorf("handle stream server error want: %v, get %v", hello, b[:nr])
		}

		// send payload to client
		if _, err := pkt.WriteTo(pl.Payload, addr); err != nil {
			t.Errorf("write payload back to client error: %v", err)
		}

		err = dg.ReceiveBuffer(rw, b)
		if err != nil {
			t.Errorf("read payload sent from server error: %v", err)
		}

		err = pl.Parse(dg.Payload.(*BytePayload).Payload)
		if err != nil {
			t.Errorf("parse payload error: %v", err)
		}

		if !bytes.Equal(pl.Payload, hello) {
			t.Errorf("handle stream client error want: %v, get %v", string(pl.Payload), string(hello))
		}
	})
}

func TestHandleStreamBind(t *testing.T) {
	t.Run("test handle stream bind", func(t *testing.T) {
		srv, err := newUDPProxyServer("", zap.NewNop())
		if err != nil {
			t.Fatalf("create UDP proxy server error")
		}

		conn, rw := net.Pipe()
		defer conn.Close()
		defer rw.Close()

		// handle proxy
		go func() {
			rc, err := net.ListenUDP("udp", nil)
			if err != nil {
				t.Errorf("connect udp server error: %v", err)
			}
			defer rc.Close()

			if err := srv.HandleStream(conn, Request("*"), rc); err != nil {
				t.Errorf("handle stream error: %v", err)
			}
		}()

		// test compression assign
		t.Run("test compression assign", func(t *testing.T) {
			// client send datagram
			dg := Datagram{
				Type: CompressionAssignValue,
			}
			pl := &CompressionAssignPayload{
				ContextID: 2,
				IPVersion: 0,
			}
			dg.Length = uint64(quicvarint.Len(2)) + 1
			dg.Payload = pl

			// send payload to server
			if err := dg.Send(rw); err != nil {
				t.Errorf("send packet error: %v", err)
			}

			b := make([]byte, 2048)
			dgr := Datagram{}
			err = dgr.ReceiveBuffer(rw, b)
			if err != nil {
				t.Errorf("read payload sent from server error: %v", err)
			}
			if dgr.Type != dg.Type {
				t.Errorf("datagram type error: want: %v, get: %v", dg.Type, dgr.Type)
			}
			plr := &CompressionAssignPayload{}

			err = plr.Parse(dgr.Payload.(*BytePayload).Payload)
			if err != nil {
				t.Errorf("parse payload error: %v", err)
			}

			if plr.ContextID != pl.ContextID {
				t.Errorf("context id error: want: %v, get: %v", pl.ContextID, plr.ContextID)
			}
			if plr.IPVersion != pl.IPVersion {
				t.Errorf("IP version error: want: %v, get:%v", pl.IPVersion, plr.IPVersion)
			}
		})

		// test compression close
		t.Run("test compression close", func(t *testing.T) {
			// client send datagram
			dg := Datagram{
				Type: CompressionCloseValue,
			}
			pl := &CompressionClosePayload{
				ContextID: 2,
			}
			dg.Length = uint64(quicvarint.Len(2))
			dg.Payload = pl

			// send payload to server
			if err := dg.Send(rw); err != nil {
				t.Errorf("send packet error: %v", err)
			}

			b := make([]byte, 2048)
			dgr := Datagram{}
			err = dgr.ReceiveBuffer(rw, b)
			if err != nil {
				t.Errorf("read payload sent from server error: %v", err)
			}
			if dgr.Type != dg.Type {
				t.Errorf("datagram type error: want: %v, get: %v", dg.Type, dgr.Type)
			}
			plr := &CompressionClosePayload{}

			err = plr.Parse(dgr.Payload.(*BytePayload).Payload)
			if err != nil {
				t.Errorf("parse payload error: %v", err)
			}

			if plr.ContextID != pl.ContextID {
				t.Errorf("context id error: want: %v, get: %v", pl.ContextID, plr.ContextID)
			}
		})

		// test uncompressed payload
		t.Run("test uncompression payload", func(t *testing.T) {
			// fmt.Println("send compression assign start")
			func() {
				// client send datagram
				dg := Datagram{
					Type: CompressionAssignValue,
				}
				pl := &CompressionAssignPayload{
					ContextID: 2,
					IPVersion: 0,
				}
				dg.Length = uint64(quicvarint.Len(2)) + 1
				dg.Payload = pl

				// send payload to server
				if err := dg.Send(rw); err != nil {
					t.Errorf("send packet error: %v", err)
				}

				b := make([]byte, 2048)
				dgr := Datagram{}
				err = dgr.ReceiveBuffer(rw, b)
				if err != nil {
					t.Errorf("read payload sent from server error: %v", err)
				}
				if dgr.Type != dg.Type {
					t.Errorf("datagram type error: want: %v, get: %v", dg.Type, dgr.Type)
				}
				plr := &CompressionAssignPayload{}

				err = plr.Parse(dgr.Payload.(*BytePayload).Payload)
				if err != nil {
					t.Errorf("parse payload error: %v", err)
				}

				if plr.ContextID != pl.ContextID {
					t.Errorf("context id error: want: %v, get: %v", pl.ContextID, plr.ContextID)
				}
				if plr.IPVersion != pl.IPVersion {
					t.Errorf("IP version error: want: %v, get:%v", pl.IPVersion, plr.IPVersion)
				}
			}()
			// fmt.Println("send compression assign stop")

			// fmt.Println("send payload")
			// send uncompressed payload before
			// create udp server
			pkt, err := net.ListenPacket("udp", "127.0.0.1:8899")
			if err != nil {
				t.Fatalf("create udp server error: %v", err)
			}
			defer pkt.Close()

			hello := []byte("Hello world!")
			dg := Datagram{
				Type: 0,
			}
			pl := UncompressedPayload{
				ContextID: 2,
				Payload:   hello,
			}
			raddr := netip.MustParseAddrPort(pkt.LocalAddr().String())
			if raddr.Addr().Is4() {
				pl.IPVersion = 4
			} else {
				pl.IPVersion = 6
			}
			pl.Addr = raddr.Addr()
			pl.Port = raddr.Port()
			dg.Length = pl.Len()
			dg.Payload = &pl

			// send payload to server
			if err := dg.Send(rw); err != nil {
				t.Errorf("send packet error: %v", err)
			}

			b := make([]byte, 2048)
			nr, addr, err := pkt.ReadFrom(b)
			if err != nil {
				t.Errorf("read packet conn error: %v", err)
			}

			if !bytes.Equal(b[:nr], pl.Payload) {
				t.Errorf("handle stream server error want: %v, get %v", hello, b[:nr])
			}

			// send payload to client
			if _, err := pkt.WriteTo(pl.Payload, addr); err != nil {
				t.Errorf("write payload back to client error: %v", err)
			}

			// fmt.Println("receive compression assign")
			// parse compression assign
			func() {
				dgr := Datagram{}
				err := dgr.ReceiveBuffer(rw, b)
				if err != nil {
					t.Errorf("read compression assign from server error: %v", err)
				}
				plr := CompressionAssignPayload{}
				err = plr.Parse(dgr.Payload.(*BytePayload).Payload)
				if err != nil {
					t.Errorf("parse compression assign error")
				}
				if dgr.Type != CompressionAssignValue {
					t.Errorf("datagram type error: want: %v, get: %v", CompressionAssignValue, dgr.Type)
				}
				if plr.ContextID != 3 {
					t.Errorf("parse compression assign context id error: want: 3, get: %v", plr.ContextID)
				}
				if plr.Port != raddr.Port() {
					t.Errorf("parse compression assign port error: want: %v, get: %v", pl.Port, raddr.Port())
				}
			}()

			fmt.Println("receive payload")
			dgr := Datagram{}
			err = dgr.ReceiveBuffer(rw, b)
			if err != nil {
				t.Errorf("read payload sent from server error: %v", err)
			}

			plr := CompressedPayload{}
			err = plr.Parse(dgr.Payload.(*BytePayload).Payload)
			if err != nil {
				t.Errorf("parse payload error: %v", err)
			}

			if dg.Type != dgr.Type {
				t.Errorf("datagram type error: want: %v, get: %v", dg.Type, dgr.Type)
			}
			if !bytes.Equal(plr.Payload, pl.Payload) {
				t.Errorf("handle stream client error want: %v, get %v", string(pl.Payload), string(plr.Payload))
			}
		})

	})
}

func TestHandleStreamBindCompressionPayload(t *testing.T) {
	srv, err := newUDPProxyServer("", zap.NewNop())
	if err != nil {
		t.Fatalf("create UDP proxy server error")
	}

	conn, rw := net.Pipe()
	defer conn.Close()
	defer rw.Close()

	// handle proxy
	go func() {
		rc, err := net.ListenUDP("udp", nil)
		if err != nil {
			t.Errorf("connect udp server error: %v", err)
		}
		defer rc.Close()

		if err := srv.HandleStream(conn, Request("*"), rc); err != nil {
			t.Errorf("handle stream error: %v", err)
		}
	}()

	t.Run("test compression payload", func(t *testing.T) {
		// create udp server
		pkt, err := net.ListenPacket("udp", "127.0.0.1:8899")
		if err != nil {
			t.Fatalf("create udp server error: %v", err)
		}
		defer pkt.Close()

		raddr := netip.MustParseAddrPort(pkt.LocalAddr().String())

		// fmt.Println("send compression assign start")
		func() {
			// client send datagram
			dg := Datagram{
				Type: CompressionAssignValue,
			}
			pl := &CompressionAssignPayload{
				ContextID: 4,
			}
			if raddr.Addr().Is4() {
				pl.IPVersion = 4
			} else {
				pl.IPVersion = 6
			}
			pl.Addr = raddr.Addr()
			pl.Port = raddr.Port()
			dg.Length = pl.Len()
			dg.Payload = pl

			// send payload to server
			if err := dg.Send(rw); err != nil {
				t.Errorf("send packet error: %v", err)
			}

			b := make([]byte, 2048)
			dgr := Datagram{}
			err = dgr.ReceiveBuffer(rw, b)
			if err != nil {
				t.Errorf("read payload sent from server error: %v", err)
			}
			if dgr.Type != dg.Type {
				t.Errorf("datagram type error: want: %v, get: %v", dg.Type, dgr.Type)
			}
			plr := &CompressionAssignPayload{}

			err = plr.Parse(dgr.Payload.(*BytePayload).Payload)
			if err != nil {
				t.Errorf("parse payload error: %v", err)
			}

			if plr.ContextID != pl.ContextID {
				t.Errorf("context id error: want: %v, get: %v", pl.ContextID, plr.ContextID)
			}
			if plr.IPVersion != pl.IPVersion {
				t.Errorf("IP version error: want: %v, get:%v", pl.IPVersion, plr.IPVersion)
			}
			if plr.Addr != pl.Addr {
				t.Errorf("parse compression addr error: want: %v, get: %v", pl.Addr, plr.Addr)
			}
			if plr.Port != pl.Port {
				t.Errorf("parse compression port error: want: %v, get: %v", pl.Addr, plr.Addr)
			}
		}()
		// fmt.Println("send compression assign stop")

		// send compressed payload before
		hello := []byte("Hello world!")
		dg := Datagram{
			Type: 0,
		}
		pl := CompressedPayload{
			ContextID: 4,
			Payload:   hello,
		}
		dg.Length = pl.Len()
		dg.Payload = &pl

		// send payload to server
		if err := dg.Send(rw); err != nil {
			t.Errorf("send packet error: %v", err)
		}

		b := make([]byte, 2048)
		nr, addr, err := pkt.ReadFrom(b)
		if err != nil {
			t.Errorf("read packet conn error: %v", err)
		}

		if !bytes.Equal(b[:nr], pl.Payload) {
			t.Errorf("handle stream server error want: %v, get %v", hello, b[:nr])
		}

		// send payload to client
		if _, err := pkt.WriteTo(pl.Payload, addr); err != nil {
			t.Errorf("write payload back to client error: %v", err)
		}

		dgr := Datagram{}
		err = dgr.ReceiveBuffer(rw, b)
		if err != nil {
			t.Errorf("read payload sent from server error: %v", err)
		}

		plr := CompressedPayload{}
		err = plr.Parse(dgr.Payload.(*BytePayload).Payload)
		if err != nil {
			t.Errorf("parse payload error: %v", err)
		}

		if dg.Type != dgr.Type {
			t.Errorf("datagram type error: want: %v, get: %v", dg.Type, dgr.Type)
		}
		if !bytes.Equal(plr.Payload, pl.Payload) {
			t.Errorf("handle stream client error want: %v, get %v", string(pl.Payload), string(plr.Payload))
		}
	})
}

func TestHandlePacket(t *testing.T) {
	/*
	srv, err := newUDPProxyServer("", zap.NewNop())
	if err != nil {
		t.Fatalf("create UDP proxy server error")
	}
	*/

	/*
		t.Run("test handle packet", func(t *testing.T) {
			str := NewMockStream(gomock.NewController(t))
			str.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(context.Context) ([]byte, error) {
				return append(quicvarint.Append([]byte{}, 0), []byte("foo")...), nil
			})
			done := make(chan struct{})
			str.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(context.Context) ([]byte, error) {
				<-done
				return append(quicvarint.Append([]byte{}, 0), []byte("foo")...), nil
			})

			closeStream := make(chan struct{})
			str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
				<-closeStream
				return 0, io.EOF
			})
			defer close(closeStream)

			// handle proxy
			go func() {
				rc, err := net.Dial("udp", "127.0.0.1:8899")
				if err != nil {
					t.Errorf("connect udp server error: %v", err)
				}
				defer rc.Close()

				if err := srv.HandlePacket(str, Request("127.0.0.1:8899"), rc.(*net.UDPConn)); err != nil {
					t.Errorf("handle stream error: %v", err)
				}
			}()

			// create udp server
			pkt, err := net.ListenPacket("udp", "127.0.0.1:8899")
			if err != nil {
				t.Fatalf("create udp server error: %v", err)
			}
			defer pkt.Close()

			b := make([]byte, 2048)
			nr, _, err := pkt.ReadFrom(b)
			if err != nil {
				t.Errorf("read packet conn error: %v", err)
			}

			if !bytes.Equal([]byte("foo"), b[:nr]) {
				t.Errorf("receive payload error: want: foo, get: %v", string(b[:nr]))
			}
		})
	*/
	t.Run("test handle packet bind", func(t *testing.T) {})
}

func TestParseRequst(t *testing.T) {
	t.Run("test parse request", func(t *testing.T) {
		tests := []struct {
			Template    string
			HttpRequest []*http.Request
			Request     []Request
		}{
			{
				Template: "https://{host}/.well-known/masque/udp/{target_host}/{target_port}/",
				HttpRequest: []*http.Request{
					{
						Method: http.MethodGet,
						URL: func() *url.URL {
							u, _ := url.Parse("https://example.com/.well-known/masque/udp/1.2.3.4/1234/")
							return u
						}(),
						Proto:      "HTTP/1.1",
						ProtoMajor: 1,
						ProtoMinor: 1,
						Header: func() http.Header {
							header := http.Header{}
							header.Set("Connection", "Upgrade")
							header.Set("Upgrade", RequestProtocol)
							return header
						}(),
					},
					{
						Method: http.MethodGet,
						URL: func() *url.URL {
							u, _ := url.Parse("https://example.com/.well-known/masque/udp/1.2.3.4/1234/")
							return u
						}(),
						Proto:      "HTTP/1.1",
						ProtoMajor: 1,
						ProtoMinor: 1,
						Header: func() http.Header {
							header := http.Header{}
							header.Set("Connection", "Upgrade")
							header.Set("Upgrade", RequestProtocol)
							header.Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
							return header
						}(),
					},
					{
						Method: http.MethodGet,
						URL: func() *url.URL {
							u, _ := url.Parse("https://example.com/.well-known/masque/udp/*/*/")
							return u
						}(),
						Proto:      "HTTP/1.1",
						ProtoMajor: 1,
						ProtoMinor: 1,
						Header: func() http.Header {
							header := http.Header{}
							header.Set("Connection", "Upgrade")
							header.Set("Upgrade", RequestProtocol)
							header.Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
							header.Set(ConnectUDPBindHeader, ConnectUDPBindHeaderValue)
							return header
						}(),
					},
					{
						Method: http.MethodConnect,
						URL: func() *url.URL {
							u, _ := url.Parse("https://example.com/.well-known/masque/udp/1.2.3.4/1234/")
							return u
						}(),
						Proto:      "HTTP/2.0",
						ProtoMajor: 2,
						ProtoMinor: 0,
						Header: func() http.Header {
							header := http.Header{}
							header.Set(":protocol", RequestProtocol)
							header.Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
							return header
						}(),
					},
					{
						Method: http.MethodConnect,
						URL: func() *url.URL {
							u, _ := url.Parse("https://example.com/.well-known/masque/udp/*/*/")
							return u
						}(),
						Proto:      "HTTP/2.0",
						ProtoMajor: 2,
						ProtoMinor: 0,
						Header: func() http.Header {
							header := http.Header{}
							header.Set(":protocol", RequestProtocol)
							header.Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
							header.Set(ConnectUDPBindHeader, ConnectUDPBindHeaderValue)
							return header
						}(),
					},
					{
						Method: http.MethodConnect,
						URL: func() *url.URL {
							u, _ := url.Parse("https://example.com/.well-known/masque/udp/1.2.3.4/1234/")
							return u
						}(),
						Proto:      RequestProtocol,
						ProtoMajor: 3,
						ProtoMinor: 0,
						Header: func() http.Header {
							header := http.Header{}
							header.Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
							return header
						}(),
					},
					{
						Method: http.MethodConnect,
						URL: func() *url.URL {
							u, _ := url.Parse("https://example.com/.well-known/masque/udp/*/*/")
							return u
						}(),
						Proto:      RequestProtocol,
						ProtoMajor: 3,
						ProtoMinor: 0,
						Header: func() http.Header {
							header := http.Header{}
							header.Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
							header.Set(ConnectUDPBindHeader, ConnectUDPBindHeaderValue)
							return header
						}(),
					},
					{
						Method: http.MethodGet,
						URL: func() *url.URL {
							u, _ := url.Parse("https://example.com/.well-known/masque/udp/google.com/443/")
							return u
						}(),
						Proto:      "HTTP/1.1",
						ProtoMajor: 1,
						ProtoMinor: 1,
						Header: func() http.Header {
							header := http.Header{}
							header.Set("Connection", "Upgrade")
							header.Set("Upgrade", RequestProtocol)
							return header
						}(),
					},
					{
						Method: http.MethodGet,
						URL: func() *url.URL {
							u, _ := url.Parse("https://example.com/.well-known/masque/udp/2001%3A0db8%3A85a3%3A0000%3A0000%3A8a2e%3A0370%3A7334/443/")
							return u
						}(),
						Proto:      "HTTP/1.1",
						ProtoMajor: 1,
						ProtoMinor: 1,
						Header: func() http.Header {
							header := http.Header{}
							header.Set("Connection", "Upgrade")
							header.Set("Upgrade", RequestProtocol)
							return header
						}(),
					},
				},
				Request: []Request{
					"1.2.3.4:1234",
					"1.2.3.4:1234",
					"*",
					"1.2.3.4:1234",
					"*",
					"1.2.3.4:1234",
					"*",
					"google.com:443",
					"[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443",
				},
			},
		}

		for _, v := range tests {
			srv, err := newUDPProxyServer(v.Template, zap.NewNop())
			if err != nil {
				t.Errorf("new proxy server with template: %s", v.Template)
			}

			for i, vv := range v.HttpRequest {
				req, err := srv.ParseRequest(vv)
				if err != nil || req != v.Request[i] {
					t.Errorf("parse request error: %v, want: %s, get: %s", err, v.Request[i], req)
				}
			}
		}
	})
}
