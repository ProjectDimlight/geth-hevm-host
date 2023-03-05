import socket
import time

UDP_IP = "192.168.1.1"
UDP_PORT = 5001
MESSAGE = b"\x05\x07\x00\x00"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))

'''
compile command
go env -w GOPROXY=https://goproxy.cn GO111MODULE=on | go run build/ci.go install ./cmd/evm
'''

