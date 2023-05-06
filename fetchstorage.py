import socket
import time

UDP_IP = "192.168.1.1"
UDP_PORT = 5001
MESSAGE = b"\x02\x04\x07\x01" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))

