import os
import sys
import socket
import random
import time

# UDP socket
UDP_IP = "192.168.1.1"
UDP_PORT = 23333
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# UDP debug
def debugEVM():
    DEBUG_MESSAGE = b'\x00\x00' + b'\x05\x07\x07\x00' + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00'
    sock.sendto(DEBUG_MESSAGE, (UDP_IP, UDP_PORT))

# UDP resetPC
def resetHEVM():
    SETPC_MESSAGE = b'\x00\x00' + b'\x02\x07\x05\x00' + b'\x00\x00\x00\x00' + b'\xE0\x01\x00\x00' + b'\x08\x00\x00\x00' + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00'
    sock.sendto(SETPC_MESSAGE, (UDP_IP, UDP_PORT))

# EVM codes
STOP    = '00'
ADD     = '01'
SUB     = '03'
POP     = '50'
MLOAD   = '51'
MSTORE  = '52'
MSTORE8 = '53'
SLOAD   = '54'
SSTORE  = '55'
JUMP    = '56'
JUMPI   = '57'
JUMPDEST= '5b'
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
            IMM_INS += byteHexTrans(random.randint(0, 0xff))[2:]
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
    loopCounter = byteHexTrans(int(1e6))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += JUMPDEST
    # loop logic here
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
    return code

"""
ADD benchmark is used to test single cycle arithmetic instruction.

ADD benchmark is designed with (PUSH PUSH ADD POP) pairs. 
"""
def addBench():
    code = ""
    loopCounter = byteHexTrans(int(1e6))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += JUMPDEST
    # loop logic here
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
    loopCounter = byteHexTrans(int(1e4))
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += PUSH_GEN(1, 'DEFAULT', '00')
    code += SSTORE
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += JUMPDEST
    # loop logic here
    code += PUSH_GEN(1, 'DEFAULT', '00')
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
    return code

def storageMissBench():
    code = ""
    loopCounter = byteHexTrans(int(1e4))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += PUSH_GEN(1, 'DEFAULT', '00')
    code += JUMPDEST
    # loop logic here
    code += DUP[1]
    code += SLOAD
    code += POP
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += ADD
    # loop logic end
    code += PUSH_GEN(1, 'DEFAULT', '01')
    code += SWAP[1]
    code += SUB
    code += DUP[1]
    code += PUSH_GEN(1, 'DEFAULT', byteHexTrans(2 + 1 + len(loopCounter) // 2))
    code += JUMPI
    code += POP
    code += STOP
    return code

"""
JUMP benchmark is used to test jump instruction : JUMP & JUMPI

JUMP benchmark is designed with several JUMPDEST and JUMP instructions. HardwareEVM will execute control flow flush when jump happen. (JUMPI equals JUMP when 0, equals normal single cycle instruction otherwise)
"""
def jumpBench():
    code = ""
    loopCounter = byteHexTrans(int(1e6))
    code += PUSH_GEN(len(loopCounter) // 2, 'DEFAULT', loopCounter)
    code += JUMPDEST
    # loop logic here
    code += PUSH_GEN(1, 'DEFAULT', '0e')
    code += PUSH_GEN(1, 'DEFAULT', '0a')
    code += PUSH_GEN(1, 'DEFAULT', '0c')
    code += (JUMP + JUMPDEST) * 3
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
benchmark contains several time benchmark of HardwareEVM.
The total time is sum of 'HardEVM execution time' + 'communication overhead'(related to code size and data migration).
"""
benchmark = {}
benchmark['LOOP']   = loopBench
benchmark['PUSH']   = pushBench
benchmark['ADD']    = addBench
benchmark['STORAGEhit']     = storageHitBench
benchmark['STORAGEmiss']    = storageMissBench

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
    os.system(".\\build\\bin\\evm --code " + code + " run")
    # reset HardwareEVM state, prepare for next execution
    resetHEVM()
    

main()
