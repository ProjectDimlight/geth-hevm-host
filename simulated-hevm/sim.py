import socket

localIP = "127.0.0.1"
localPort = 23333
bufSize = 2048

ECP_NONE      = 0
ECP_CALL      = 1
ECP_COPY      = 2
ECP_SWAP      = 3
ECP_END       = 4
ECP_DEBUG			= 5

ECP_CONTROL   = 0
ECP_CODE      = 1
ECP_CALLDATA  = 2
ECP_MEM       = 3
ECP_STORAGE   = 4
ECP_HOST      = 5
ECP_ENV				= 6

def main():
  udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udp_socket.bind((localIP, localPort))
  
  data, address = udp_socket.recvfrom(2048)
  data, address = udp_socket.recvfrom(2048)
  data, address = udp_socket.recvfrom(2048)
  data, address = udp_socket.recvfrom(2048)

  # ECP
  # op
  # from
  # to
  # reserved
  # src offset
  # dst offset
  # len
  # == data ==
  # pc
  # gas
  # stack size
  # stack contents (16 at most)
  send_data = \
    ECP_DEBUG.to_bytes(1, "little") + \
    ECP_CONTROL.to_bytes(1, "little") + \
    ECP_HOST.to_bytes(1, "little") + \
    int(0).to_bytes(1, "little") + \
    int(0).to_bytes(4, "little") + \
    int(0).to_bytes(4, "little") + \
    int(20).to_bytes(4, "little") + \
    int(0).to_bytes(4, "little") + \
    int(100000).to_bytes(8, "little") + \
    int(2).to_bytes(4, "little") + \
    int(114514).to_bytes(32, "little") + \
    int(1919810).to_bytes(32, "little")

  udp_socket.sendto(send_data, address)
  
  # ECP
  # op
  # from
  # to
  # reserved
  # src offset
  # dst offset
  # len
  # == data ==
  # num_of_items
  # [key, value]
  send_data = \
    ECP_SWAP.to_bytes(1, "little") + \
    ECP_STORAGE.to_bytes(1, "little") + \
    ECP_HOST.to_bytes(1, "little") + \
    int(0).to_bytes(1, "little") + \
    int(0).to_bytes(4, "little") + \
    int(0).to_bytes(4, "little") + \
    int(20).to_bytes(4, "little") + \
    int(3).to_bytes(4, "little") + \
    int(0x1000000020000000).to_bytes(32, "little") + \
    int(114514).to_bytes(32, "little") + \
    int(0x3000000040000000).to_bytes(32, "little") + \
    int(1919810).to_bytes(32, "little") + \
    int(0x5000000060000000).to_bytes(32, "little") + \
    int(0xdeadbeef).to_bytes(32, "little") + \
    int(2).to_bytes(4, "little") + \
    int(0x7000000080000000).to_bytes(32, "little") + \
    int(0x3000000040000000).to_bytes(32, "little") 

  udp_socket.sendto(send_data, address)

  data, address = udp_socket.recvfrom(2048)

  print("op = ", data[0])
  print("src = ", data[1])
  print("dest = ", data[2])

  cnt = int.from_bytes(data[16:20], "little")
  print("items = ", cnt)
  for i in range(cnt):
    offset = 20 + i * 64
    print("{}: {}".format(int.from_bytes(data[offset:offset + 32], "little"), int.from_bytes(data[offset + 32:offset + 64], "little")))

  udp_socket.close()

main()