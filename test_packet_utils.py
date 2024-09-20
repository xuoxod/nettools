import unittest
import socket
from packet_sender import calculate_checksum


class TestPacketUtils(unittest.TestCase):

    def test_calculate_checksum(self):
        # Test case 1: Valid IP header
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20,
            12345,
            0,
            64,
            socket.IPPROTO_TCP,
            0,
            socket.inet_aton("192.168.1.1"),
            socket.inet_aton("192.168.1.10"),
        )
        self.assertEqual(calculate_checksum(ip_header), 0x449C)

        # Test case 2: Valid TCP header
        tcp_header = struct.pack(
            "!HHLLBBHHH", 1234, 5678, 12345678, 87654321, 20, 0, 1024, 0, 0
        )
        self.assertEqual(calculate_checksum(tcp_header), 0x7C9B)


if __name__ == "__main__":
    unittest.main()
