import os
import sys
import socket
import random
import time

# UDP socket
UDP_IP = "192.168.1.1"
UDP_PORT = 5001
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# UDP debug
def debugEVM():
    DEBUG_MESSAGE = b'\x05\x07\x07\x00' + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00'
    sock.sendto(DEBUG_MESSAGE, (UDP_IP, UDP_PORT))

# UDP resetPC
def resetHEVM():
    SETPC_MESSAGE = b'\x02\x07\x05\x00' + b'\x00\x00\x00\x00' + b'\xE0\x01\x00\x00' + b'\x08\x00\x00\x00' + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00'
    sock.sendto(SETPC_MESSAGE, (UDP_IP, UDP_PORT))

# EVM codes
STOP    = '00'
ADD     = '01'
SUB     = '03'
SHA3    = '20'
POP     = '50'
MLOAD   = '51'
MSTORE  = '52'
MSTORE8 = '53'
SLOAD   = '54'
SSTORE  = '55'
JUMP    = '56'
JUMPI   = '57'
JUMPDEST= '5b'
PC      = '58'
MSIZE   = '59'

PUSH = {}
for i in range(32):
    PUSH[i + 1] = hex(i + 0x60)[2:]
DUP = {}
for i in range(16):
    DUP[i + 1] = hex(i + 0x80)[2:]
SWAP = {}
for i in range(16):
    SWAP[i + 1] = hex(i + 0x90)[2:]

"""
Transform a int to ByteAllign Hex.
"""
def byteHexTrans(val):
    hexString = hex(val)[2:]
    if len(hexString) & 1:
        hexString = '0' + hexString
    return hexString

"""
PUSH_GEN generate PUSH instruction according configuration.
IMM_BYTE_LEN defines immediate number's length in byte.
IMM_TYPE:
    'DEFAULT'   : number filled with 0x01
    'RANDOM'    : number filled with random number
"""
def PUSH_GEN(IMM_BYTE_LEN, IMM_TYPE = 'DEFAULT', defaultValue = None):
    IMM_INS = ''
    if IMM_TYPE == 'DEFAULT':
        IMM_INS += defaultValue
    elif IMM_TYPE == 'RANDOM':
        for i in range(IMM_BYTE_LEN):
            IMM_INS += byteHexTrans(random.randint(0, 0xff))
    return PUSH[IMM_BYTE_LEN] + IMM_INS

"""
LOOP benchmark is used to test basic framework: loop

Since the length of code is strongly related to communication time, each benchmark should execute code as short as possible, which means use loop structure to run single instruction many times. This benchmark is desgned with loop.
"""
def loopBench():
    code = ""
    loopCounter = byteHexTrans(int(1e6))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += JUMPDEST
    # loop logic here
    # loop logic end
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += SWAP[1]
    code += SUB
    code += DUP[1]
    code += PUSH_GEN(1, 'DEFAULT', byteHexTrans(1 + len(loopCounter) // 2))
    code += JUMPI
    code += POP
    code += STOP
    return code

"""
PUSH benchmark is used to test basic instruction : PUSH & POP

PUSH benchmark is designed with same number PUSH and POP instructions. HardwareEVM will execute (PUSH & POP) pairs. Since the execution time is only related to hardware frequency and instruction type, here use only 'PUSH1 1' to test.
"""
def pushBench():
    code = ""
    loopCounter = byteHexTrans(int(1e5))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += JUMPDEST
    # loop logic here
    for i in range(1000):
        code += PUSH_GEN(1, 'RANDOM')
        code += POP
    # loop logic end
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += SWAP[1]
    code += SUB
    code += DUP[1]
    code += PUSH_GEN(1, 'DEFAULT', byteHexTrans(1 + len(loopCounter) // 2))
    code += JUMPI
    code += POP
    code += STOP
    print("1e8 times (PUSH, POP) operation")
    return code

"""
ADD benchmark is used to test single cycle arithmetic instruction.

ADD benchmark is designed with (PUSH PUSH ADD POP) pairs. 
"""
def addBench():
    code = ""
    loopCounter = byteHexTrans(int(2e5))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += JUMPDEST
    # loop logic here
    for i in range(500):
        code += PUSH_GEN(1, 'RANDOM')
        code += PUSH_GEN(1, 'RANDOM')
        code += ADD
        code += POP
    # loop logic end
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += SWAP[1]
    code += SUB
    code += DUP[1]
    code += PUSH_GEN(1, 'DEFAULT', byteHexTrans(1 + len(loopCounter) // 2))
    code += JUMPI
    code += POP
    code += STOP
    print("1e8 times (PUSH, PUSH, ADD, POP) operation")
    return code

"""
STORAGE benchmark is used to test storage instruction.
STORAGE benchmark is divided into [hit, miss, real] parts.

storageHitBench is designed with storage access with same address, which results in hit.
storageMissBench is designed with storage access with ascending address, which results in miss.
storageRealBench is designed with some 'warm' address and other 'cold' address. 'warm' address will be accessed with 80% times in total, and 'cold' address shares the remain.
"""
def storageHitBench():
    code = ""
    loopCounter = byteHexTrans(int(2e4))
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += PUSH_GEN(1, 'DEFAULT', '00')
    code += SSTORE
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += JUMPDEST
    # loop logic here
    for i in range(500):
        code += PUSH_GEN(1, 'DEFAULT', '00')
        code += SLOAD
        code += POP
    # loop logic end
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += SWAP[1]
    code += SUB
    code += DUP[1]
    code += PUSH_GEN(1, 'DEFAULT', byteHexTrans(5 + 1 + len(loopCounter) // 2))
    code += JUMPI
    code += POP
    code += STOP
    print("1e7 times (PUSH, hit-SLOAD, POP) operation")
    return code

def storageMissOCMBench():
    code = ""
    loopCounter = byteHexTrans(int(300))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += JUMPDEST
    # loop logic here
    for i in range(2):
        code += PUSH_GEN(1, 'DEFAULT', '00')
        code += SLOAD
        code += POP
        code += PUSH_GEN(1, 'DEFAULT', '40')
        code += SLOAD
        code += POP
    # loop logic end
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += SWAP[1]
    code += SUB
    code += DUP[1]
    code += PUSH_GEN(1, 'DEFAULT', byteHexTrans(1 + len(loopCounter) // 2))
    code += JUMPI
    code += POP
    code += STOP
    print("1e5 times (PUSH, miss-SLOAD, POP) operation")
    return code

def storageMissHostBench():
    code = ""
    for i in range(600):
        index = byteHexTrans(i * 64)
        code += PUSH_GEN(len(index) // 2, 'DEFAULT', index)
        code += SLOAD
        code += POP
    code += STOP
    print("1e5 times (PUSH, miss-SLOAD, POP) operation")
    return code

"""
JUMP benchmark is used to test jump instruction : JUMP & JUMPI

JUMP benchmark is designed with several JUMPDEST and JUMP instructions. HardwareEVM will execute control flow flush when jump happen. (JUMPI equals JUMP when 0, equals normal single cycle instruction otherwise)
"""
def jumpFalseBench():
    code = ""
    loopCounter = byteHexTrans(int(2e5))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += JUMPDEST
    length = 1 + len(loopCounter) // 2 + 1
    # loop logic here
    for i in range(500):
        code += PUSH_GEN(1, 'DEFAULT', '00')
        code += PUSH_GEN(1, 'DEFAULT', byteHexTrans(1 + len(loopCounter) // 2))
        code += JUMPI
    # loop logic end
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += SWAP[1]
    code += SUB
    code += DUP[1]
    code += PUSH_GEN(1, 'DEFAULT', byteHexTrans(1 + len(loopCounter) // 2))
    code += JUMPI
    code += POP
    code += STOP
    print("1e8 times false-JUMPI operation")
    return code

def jumpTrueBench():
    code = ""
    loopCounter = byteHexTrans(int(2e5))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += JUMPDEST
    length = 1 + len(loopCounter) // 2 + 1
    # loop logic here
    loopTimes = 500
    for i in range(loopTimes):
        code += PUSH_GEN(1, 'DEFAULT', '01')
        addr = byteHexTrans(length + loopTimes * 7 + 9 - 2 * i)
        if len(addr) == 2:
            addr = '00' + addr
        code += PUSH_GEN(2, 'DEFAULT', addr)
    addr = byteHexTrans(length + loopTimes * 7 + 9 - 2)
    if len(addr) == 2:
            addr = '00' + addr
    code += PUSH_GEN(2, "DEFAULT", addr)
    code += JUMP
    code += JUMPDEST
    addr = byteHexTrans(length + loopTimes * 7 + 9)
    if len(addr) == 2:
            addr = '00' + addr
    code += PUSH_GEN(2, "DEFAULT", addr)
    code += JUMP
    for i in range(loopTimes):
        code += JUMPDEST
        code += JUMPI
    code += JUMPDEST
    # loop logic end
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += SWAP[1]
    code += SUB
    code += DUP[1]
    code += PUSH_GEN(1, 'DEFAULT', byteHexTrans(1 + len(loopCounter) // 2))
    code += JUMPI
    code += POP
    code += STOP
    print("1e8 times true-JUMPI operation")
    return code

def hashBench():
    code = ""
    loopCounter = byteHexTrans(int(2e4))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += PUSH_GEN(32, 'RANDOM') + PUSH_GEN(1, 'DEFAULT', '00') + MSTORE
    code += JUMPDEST
    # loop logic here
    for i in range(500):
        code += PUSH_GEN(1, 'DEFAULT', '20')
        code += PUSH_GEN(1, 'DEFAULT', '00')
        code += SHA3
        code += POP
    # loop logic end
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += SWAP[1]
    code += SUB
    code += DUP[1]
    code += PUSH_GEN(1, 'DEFAULT', byteHexTrans(1 + len(loopCounter) // 2 + 36))
    code += JUMPI
    code += POP
    code += STOP
    print("1e7 times (PUSH, PUSH, 32byte-SHA3, POP) operation")
    return code

def memoryHitBench():
    code = ""
    loopCounter = byteHexTrans(int(2e5))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += PUSH_GEN(32, 'RANDOM') + PUSH_GEN(1, 'DEFAULT', '00') + MSTORE
    code += JUMPDEST
    # loop logic here
    for i in range(500):
        code += PUSH_GEN(1, "DEFAULT", byteHexTrans(random.randint(0, 0x20)))
        code += MLOAD
        code += POP
    # loop logic end
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += SWAP[1]
    code += SUB
    code += DUP[1]
    code += PUSH_GEN(1, 'DEFAULT', byteHexTrans(1 + len(loopCounter) // 2 + 36))
    code += JUMPI
    code += POP
    code += STOP
    print("1e8 times (PUSH, MLOAD, POP) operation")
    return code

def stackBench():
    code = ""
    loopCounter = byteHexTrans(int(1e5))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += JUMPDEST
    # loop logic here
    for i in range(20):
        code += PUSH_GEN(1, "DEFAULT", byteHexTrans(i))
    for i in range(1000):
        code += DUP[(i % 16) + 1]
        code += SWAP[(i % 16) + 1]
        code += POP
    for i in range(20):
        code += POP
    # loop logic end
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += SWAP[1]
    code += SUB
    code += DUP[1]
    code += PUSH_GEN(1, 'DEFAULT', byteHexTrans(1 + len(loopCounter) // 2))
    code += JUMPI
    code += POP
    code += STOP
    print("1e8 times (SWAP, DUP, POP) operation")
    return code

def pcBench():
    code = ""
    loopCounter = byteHexTrans(int(1e5))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += JUMPDEST
    # loop logic here
    for i in range(1000):
        code += PC
        code += POP
    # loop logic end
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += SWAP[1]
    code += SUB
    code += DUP[1]
    code += PUSH_GEN(1, 'DEFAULT', byteHexTrans(1 + len(loopCounter) // 2))
    code += JUMPI
    code += POP
    code += STOP
    print("1e8 times PC operation")
    return code

def functional():
    return "600160020160005560043560015560206007600f37600051600255600a600060203960205160035560005460029003600455600160026003826005555050506300114514600052600a5b60019003808053806049575160065558600755306008553360095546600a5559600b5500"

"""
benchmark contains several time benchmark of HardwareEVM.
The total time is sum of 'HardEVM execution time' + 'communication overhead'(related to code size and data migration).
"""
benchmark = {}
benchmark['LOOP']   = loopBench
benchmark['PUSH']   = pushBench
benchmark['ADD']    = addBench
benchmark['JUMPtrue']           = jumpTrueBench
benchmark['JUMPfalse']          = jumpFalseBench
benchmark['STORAGEhit']         = storageHitBench
benchmark['STORAGEmissOCM']     = storageMissOCMBench
benchmark['STORAGEmissHost']    = storageMissHostBench
benchmark['MEMORYhit']          = memoryHitBench
benchmark['FUNC']   = functional
benchmark['HASH']   = hashBench
benchmark['STACK']  = stackBench
benchmark['PC']     = pcBench

def main():
    if len(sys.argv) != 2:
        print("args should contain supported benchmark name")
        return
    testbench = sys.argv[1]
    if benchmark.get(testbench) == None:
        print("input testbench is not supported")
        return
    print("Use time benchmark " + testbench)
    code = benchmark[testbench]()
    with open("bytecode", "w") as f:
        f.write(code)
    # print(code)
    os.system(".\\build\\bin\\evm --codefile " + 'bytecode' + " run")

main()
