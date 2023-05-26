import socket

from icmp import Icmp
from const import PORT, DATA_TO_RECV


def get_whois_data(address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    sock.connect((socket.gethostbyname('whois.iana.org'), 43))
    sock.send((address + '\r\n').encode('utf-8'))
    result = {}
    try:
        first_data = sock.recv(1024).decode()
        if 'refer' in first_data:
            refer_ind = first_data.index('refer')
            first_data = first_data[refer_ind:].split('\n')[0].replace(' ', '').split(':')
            server_name = first_data[1]
            whois_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            whois_sock.connect((server_name, 43))
            whois_sock.send((address + '\r\n').encode('utf-8'))
            data = b''
            current_part = whois_sock.recv(DATA_TO_RECV)
            while current_part != b'':
                data += current_part
                current_part = whois_sock.recv(DATA_TO_RECV)
            data = data.decode().lower()
            for i in ['country', 'origin', 'originas']:
                if i in data:
                    ind = data.index(i)
                    record = data[ind:].split('\n')[0]
                    record = record.replace(' ', '').split(':')
                    result[record[0]] = record[1]
            return result
    except socket.timeout:
        pass
    finally:
        sock.close()
        return result


class Data:
    def __init__(self, address, whois_data):
        self.address = address
        self.name = ''
        try:
            self.name = socket.gethostbyaddr(address)[0]
        except socket.herror:
            pass
        self.country = ''
        self.auto_sys = ''
        if 'country' in whois_data and 'EU' not in whois_data["country"]:
            self.country = whois_data["country"]
        if 'origin' in whois_data:
            self.auto_sys = whois_data['origin']
        if "originas" in whois_data:
            self.auto_sys = whois_data['originas']

    def __str__(self):
        result = f'{self.address}\n'
        if self.name and not self.auto_sys and not self.country:
            result += f'local\n'
        elif self.name:
            result += f'{self.name}, '
        if self.auto_sys and not self.country:
            result += f'{self.auto_sys}\n'
        elif self.auto_sys:
            result += f'{self.auto_sys}, '
        if self.country:
            result += f'{self.country}\n'
        return result


class Traceroute:
    def __init__(self, host: str, max_ttl: int):
        self._host = socket.gethostbyname(host)
        self._max_ttl = max_ttl

    @property
    def trace(self):
        ttl = 1
        while ttl <= self._max_ttl:
            send_sock, recv_sock = self.create(ttl)
            icmp_pack = Icmp(8, 0)
            send_sock.sendto(bytes(icmp_pack), (self._host, PORT))
            try:
                data, address = recv_sock.recvfrom(DATA_TO_RECV)
            except socket.timeout:
                yield '*\n'
                ttl += 1
                continue
            whois_data = get_whois_data(address[0])
            yield Data(address[0], whois_data)
            recv_icmp = Icmp.from_bytes(data[20:])
            if recv_icmp.type == recv_icmp.code == 0:
                send_sock.close()
                recv_sock.close()
                break
            ttl += 1
            send_sock.close()
            recv_sock.close()

    @staticmethod
    def create(ttl):
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(4)
        return send_sock, recv_sock
