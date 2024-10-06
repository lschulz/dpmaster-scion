#!/usr/bin/env python3

import socket
import time
import unittest
from ipaddress import IPv4Address, IPv6Address
from typing import List, Mapping, Optional, Tuple

from pan import udp


class BaseTest(unittest.TestCase):
    """Abstract base class for tests"""

    def send_heartbeat(self, protocol: bytes = b"QuakeArena-1") -> None:
        """Send a heartbeat to the master server."""
        msg = b"\xff\xff\xff\xffheartbeat %b\x0a" % protocol
        self._conn.write(msg)

    def expect_getinfo(self) -> bytes:
        """Expect a getinfo message from the master server.
        Returns the challenge string.
        """
        msg = self._conn.read()
        header = b"\xff\xff\xff\xffgetinfo "
        self.assertGreater(len(msg), len(header))
        self.assertEqual(msg[0:len(header)], header)
        challenge = msg[len(header):]
        return challenge

    def send_info_response(self, info: Mapping[bytes, bytes]) -> None:
        """Send an info response message to the master server."""
        msg = b"\xff\xff\xff\xffinfoResponse\x0a"
        for key, value in info.items():
            msg += b"\\%b\\%b" % (key, value)
        self._conn.write(msg)

    def send_getservers(self, game_name: bytes = b"", protocol: int = 67, args: bytes = b"") -> None:
        """Send a getservers message to the master server."""
        msg = b"\xff\xff\xff\xffgetservers %b %d %b" % (game_name, protocol, args)
        self._conn.write(msg)

    def send_getservers_ext(self, game_name:bytes = b"Quake3Arena", protocol:int = 67, args: bytes = b"") -> None:
        """Send a getserversExt message to the master server."""
        msg = b"\xff\xff\xff\xffgetserversExt %b %d %b" % (game_name, protocol, args)
        self._conn.write(msg)

    def expect_getservers_response(self) -> List[Tuple[None, IPv4Address, int]]:
        """Expect getserversResponse packets from the master server."""
        header = b"\xff\xff\xff\xffgetserversResponse"
        servers = []
        while True:
            msg = self._conn.read()
            self.assertGreater(len(msg), len(header))
            self.assertEqual(msg[0:len(header)], header)
            srv_list = msg[len(header):]
            while len(srv_list) > 0:
                self.assertEqual(srv_list[0], ord(b"\\"))
                if srv_list[1:7] == b"EOT\0\0\0":
                    return servers
                else:
                    ip = IPv4Address(int.from_bytes(srv_list[1:5], 'big'))
                    port = int.from_bytes(srv_list[5:7], 'big')
                    servers.append((None, ip, port))
                srv_list = srv_list[7:]

    def expect_getservers_ext_response(self) -> List[Tuple[Optional[int], IPv4Address|IPv6Address, int]]:
        """Expect getserversResponseExt packets from the master server."""
        header = b"\xff\xff\xff\xffgetserversExtResponse"
        servers = []
        while True:
            msg = self._conn.read()
            self.assertGreater(len(msg), len(header))
            self.assertEqual(msg[0:len(header)], header)
            srv_list = msg[len(header):]
            while len(srv_list) > 0:
                self.assertIn(srv_list[0], [ord(b"/"), ord(b"\\"), ord(b"$")])
                if srv_list[0] == ord(b"\\"):
                    # IPv4
                    if srv_list[1:7] == b"EOT\0\0\0":
                        return servers
                    ip = IPv4Address(srv_list[1:5])
                    port = int.from_bytes(srv_list[5:7], 'big')
                    servers.append((None, ip, port))
                    srv_list = srv_list[7:]
                elif srv_list[0] == ord(b"/"):
                    # IPv6
                    ip = IPv6Address(srv_list[1:17])
                    port = int.from_bytes(srv_list[17:19], 'big')
                    servers.append((None, ip, port))
                    srv_list = srv_list[19:]
                elif srv_list[0] == ord(b"$"):
                    if srv_list[1] == ord(b"\\"):
                        # SCION + IPv4
                        ia = int.from_bytes(srv_list[2:10], 'big')
                        ip = IPv4Address(srv_list[10:14])
                        port = int.from_bytes(srv_list[14:16], 'big')
                        servers.append((ia, ip, port))
                        srv_list = srv_list[16:]
                    elif srv_list[1] == ord(b"/"):
                        # SCION + IPv6
                        ia = int.from_bytes(srv_list[2:10], 'big')
                        ip = IPv6Address(srv_list[10:26])
                        port = int.from_bytes(srv_list[26:28], 'big')
                        servers.append((ia, ip, port))
                        srv_list = srv_list[28:]
                    else:
                        self.fail()


class IPv4Conn:
    """Test using an IPv4 connection"""

    def setUp(self):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__sock.settimeout(1.0)
        self.__sock.connect(("127.0.0.1", 27950))

    def tearDown(self):
        self.__sock.close()

    def get_local(self) -> Tuple[None, IPv4Address, int]:
        ip, port = self.__sock.getsockname()
        return None, IPv4Address(ip), port

    def write(self, msg: bytes) -> int:
        return self.__sock.send(msg)

    def read(self) -> bytes:
        return self.__sock.recv(2048)


class IPv6Conn:
    """Test using an IPv6 connection"""

    def setUp(self):
        self.__sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.__sock.settimeout(1.0)
        self.__sock.connect(("::1", 27950))

    def get_local(self) -> Tuple[None, IPv6Address, int]:
        ip, port, _, _ = self.__sock.getsockname()
        return None, IPv6Address(ip), port

    def tearDown(self):
        self.__sock.close()

    def write(self, msg: bytes) -> int:
        return self.__sock.send(msg)

    def read(self) -> bytes:
        return self.__sock.recv(2048)


class ScionConn:
    """Test using a SCION connection"""

    def setUp(self):
        remote = udp.resolveUDPAddr("1-ff00:0:110,127.0.0.1:27951")
        self.__conn = udp.Conn(remote)

    def tearDown(self):
        self.__conn.close()

    def get_local(self) -> Tuple[int, IPv4Address|IPv6Address, int]:
        local = self.__conn.local()
        return local.get_ia(), local.get_ip(), local.get_port()

    def write(self, msg: bytes) -> int:
        return self.__conn.write(msg)

    def read(self) -> bytes:
        self.__conn.set_read_deadline(1.0)
        return self.__conn.read()


class TestHeartbeat(BaseTest):
    def setUp(self):
        super().setUp()
        self._conn = None
        self._ipv4 = IPv4Conn()
        self._ipv4.setUp()
        self._ipv6 = IPv6Conn()
        self._ipv6.setUp()
        self._scion = ScionConn()
        self._scion.setUp()

    def tearDown(self):
        super().tearDown()
        self._ipv4.tearDown()
        self._ipv6.tearDown()
        self._scion.tearDown()

    def heartbeat(self):
        self.send_heartbeat()
        challenge = self.expect_getinfo()
        self.send_info_response({
            b"challenge": challenge,
            b"protocol": b"67",
            b"sv_maxclients": b"8",
            b"clients": b"0"
        })

    def get_servers(self):
        self.send_getservers(args=b"empty full")
        servers = self.expect_getservers_response()
        self.assertIn(self._conn.get_local(), servers)

    def get_servers_ext(self):
        self.send_getservers_ext(args=b"empty full")
        servers = self.expect_getservers_ext_response()
        self.assertIn(self._conn.get_local(), servers)

    def test_heartbeat_ipv4(self):
        self._conn = self._ipv4
        self.heartbeat()
        time.sleep(0.1)
        self.get_servers()
        self.get_servers_ext()

    def test_heartbeat_ipv6(self):
        self._conn = self._ipv6
        self.heartbeat()
        time.sleep(0.1)
        self.get_servers_ext()

    def test_heartbeat_scion(self):
        self._conn = self._scion
        self.heartbeat()
        time.sleep(0.1)
        self.get_servers_ext()


if __name__ == "__main__":
    unittest.main()
