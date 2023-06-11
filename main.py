import argparse
import socket

from traceroute import Traceroute

parser = argparse.ArgumentParser()
parser.add_argument('host', type=str, help='Имя хоста')
parser.add_argument("--ttl", type=int, help='Максимальное число шагов', default=15)


args = parser.parse_args()
count = 1
try:
    for i in Traceroute(args.host, args.ttl).trace:
        print(f'{count}. {i}')
        count += 1
except PermissionError:
    print('Необходимы права администратора')
except socket.gaierror:
    print('Неверно указан хост')
