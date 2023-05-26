import struct
import random


class Icmp:
    def __init__(self, type, code):
        self.type = type
        self.code = code

    @classmethod
    def from_bytes(cls, data: bytes):
        icmp_type, icmp_code = struct.unpack('!BB', data[:2])
        return cls(icmp_type, icmp_code)

    @classmethod
    def get_checksum(cls, msg: bytes) -> int:
        checksum = 0
        for i in range(0, len(msg), 2):
            part = (msg[i] << 8) + (msg[i + 1])
            checksum += part
        checksum = (checksum >> 16) + (checksum & 0xffff)

        return checksum ^ 0xffff

    def __bytes__(self) -> bytes:
        mock_data = struct.pack('!BBH', self.type, self.code, 0)
        current_sum = self.get_checksum(mock_data)
        return struct.pack('!BBHHH', self.type, self.code,
                           current_sum, 1, random.randint(256, 3000))
