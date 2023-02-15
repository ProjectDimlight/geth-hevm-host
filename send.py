import socket
import time

UDP_IP = "192.168.1.1"
UDP_PORT = 5001
MESSAGE = "HELLO WORLD"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(MESSAGE.encode(), (UDP_IP, UDP_PORT))

'''
compile command
go env -w GOPROXY=https://goproxy.cn GO111MODULE=on | go run build/ci.go install ./cmd/evm
'''

