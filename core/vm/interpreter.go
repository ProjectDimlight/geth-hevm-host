// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"hash"
	"net"
	"fmt"
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
	
  "github.com/lunux2008/xulu"
)

const (
	ECP_CALL_CREATE       = 0x10
	ECP_CALL_CALL		 			= 0x11
	ECP_CALL_CALLCODE			= 0x12
	ECP_CALL_DELEGATECALL = 0x14
	ECP_CALL_CREATE2			= 0x15
	ECP_CALL_STATICCALL		= 0x1a
)

const (
	ECP_END_STOP					= 0x0
	ECP_END_RETURN    		= 0x13
	ECP_END_REVERT 				= 0x1d
	ECP_END_SELFDESTRUCT 	= 0x1f
)

const (
	ECP_QUERY_BALANCE 	  = 0x11
	ECP_QUERY_EXTCODESIZE = 0x1b
	ECP_QUERY_EXTCODECOPY = 0x1c
	ECP_QUERY_EXTCODEHASH = 0x1f
	ECP_QUERY_BLOCKHASH 	= 0x0
)

const (
	ECP_NONE byte = 0
	ECP_CALL      = 1
	ECP_COPY      = 2
	ECP_SWAP      = 3
	ECP_END       = 4
	ECP_DEBUG			= 5
	ECP_QUERY 		= 6
)

const (
	ECP_CONTROL  byte = 0
	ECP_CODE          = 1
	ECP_CALLDATA      = 2
	ECP_MEM           = 3
	ECP_STORAGE       = 4
	ECP_ENV           = 5
	ECP_STACK 				= 6
	ECP_HOST				  = 7
	ECP_RETURN_DATA	  = 8
)

// Config are the configuration options for the Interpreter
type Config struct {
	Debug                   bool      // Enables debugging
	Tracer                  EVMLogger // Opcode logger
	NoBaseFee               bool      // Forces the EIP-1559 baseFee to 0 (needed for 0 price calls)
	EnablePreimageRecording bool      // Enables recording of SHA3/keccak preimages

	JumpTable *JumpTable // EVM instruction table, automatically populated if unset

	ExtraEips []int // Additional EIPS that are to be enabled
}

// ScopeContext contains the things that are per-call, such as stack and memory,
// but not transients like pc and gas
type ScopeContext struct {
	Memory   *Memory
	Stack    *Stack
	Contract *Contract
}

// keccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type keccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

type Network struct {
	conn 	 *net.UDPConn
	bufIn  []byte
	bufOut []byte
}

func NewNetwork() *Network {
	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:23334")
	raddr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 23333}
	conn, err := net.DialUDP("udp", laddr, &raddr)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return &Network{
		conn: conn,
	  bufIn: make([]byte, 2048),
		bufOut: make([]byte, 0, 2048),
	}
}

// EVMInterpreter represents an EVM interpreter
type EVMInterpreter struct {
	evm *EVM
	cfg Config
	net *Network

	hasher    keccakState // Keccak256 hasher instance shared across opcodes
	hasherBuf common.Hash // Keccak256 hasher result array shared aross opcodes

	readOnly   bool   // Whether to throw on stateful modifications
	returnData []byte // Last CALL's return data for subsequent reuse
}

// NewEVMInterpreter returns a new instance of the Interpreter.
func NewEVMInterpreter(evm *EVM, cfg Config) *EVMInterpreter {
	// If jump table was not initialised we set the default one.
	if cfg.JumpTable == nil {
		switch {
		case evm.chainRules.IsMerge:
			cfg.JumpTable = &mergeInstructionSet
		case evm.chainRules.IsLondon:
			cfg.JumpTable = &londonInstructionSet
		case evm.chainRules.IsBerlin:
			cfg.JumpTable = &berlinInstructionSet
		case evm.chainRules.IsIstanbul:
			cfg.JumpTable = &istanbulInstructionSet
		case evm.chainRules.IsConstantinople:
			cfg.JumpTable = &constantinopleInstructionSet
		case evm.chainRules.IsByzantium:
			cfg.JumpTable = &byzantiumInstructionSet
		case evm.chainRules.IsEIP158:
			cfg.JumpTable = &spuriousDragonInstructionSet
		case evm.chainRules.IsEIP150:
			cfg.JumpTable = &tangerineWhistleInstructionSet
		case evm.chainRules.IsHomestead:
			cfg.JumpTable = &homesteadInstructionSet
		default:
			cfg.JumpTable = &frontierInstructionSet
		}
		for i, eip := range cfg.ExtraEips {
			copy := *cfg.JumpTable
			if err := EnableEIP(eip, &copy); err != nil {
				// Disable it, so caller can check if it's activated or not
				cfg.ExtraEips = append(cfg.ExtraEips[:i], cfg.ExtraEips[i+1:]...)
				log.Error("EIP activation failed", "eip", eip, "error", err)
			}
			cfg.JumpTable = &copy
		}
	}

	return &EVMInterpreter{
		evm: evm,
		cfg: cfg,
		net: NewNetwork(),
	}
}

func append256FromUint(buf []byte, val uint64) []byte {
	var tmp [32]byte
	binary.LittleEndian.PutUint64(tmp[:8], val)
	return append(buf, tmp[:]...)
}

func swapEndian(val []byte) []byte {
	n := len(val)
	var tmp = make([]byte, n)
	for i := 0; i < n; i++ {
		tmp[n-1-i] = val[i];
	}
	return tmp
}

func append256FromBigEndianBytes(buf []byte, val []byte) []byte {
	var tmp [32]byte
	n := len(val)
	for i := 0; i < n; i++ {
		tmp[n-1-i] = val[i];
	}
	return append(buf, tmp[:]...)
}

func newUint256FromLittleEndianBytes(val []byte) *uint256.Int {
	var tmp [32]byte
	n := len(val)
	for i := 0; i < n; i++ {
		tmp[n-1-i] = val[i];
	}
	return uint256.NewInt(0).SetBytes(tmp[:])
}

func (in *EVMInterpreter) loadContextToHardware(callContext *ScopeContext, pc uint64) {
	contract := callContext.Contract

	// ECP starts with 2 zero bytes to keep alignment
	in.net.bufOut = in.net.bufOut[:0]
	in.net.bufOut = append(in.net.bufOut, 0)
	in.net.bufOut = append(in.net.bufOut, 0)

	// Copy Code
	// op, src, dest, padding
	in.net.bufOut = append(in.net.bufOut, ECP_COPY)
	in.net.bufOut = append(in.net.bufOut, ECP_HOST)
	in.net.bufOut = append(in.net.bufOut, ECP_CODE)
	in.net.bufOut = append(in.net.bufOut, 0)
	// src offset, dest offset, length
	in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, 0)
	in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, 0)
	in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, (uint32)(len(contract.Code)))
	in.net.bufOut = append(in.net.bufOut, contract.Code...)
	in.net.conn.Write(in.net.bufOut)

	// Copy Calldata (Input)
	// op, src, dest, padding
	in.net.bufOut = in.net.bufOut[:2]
	in.net.bufOut = append(in.net.bufOut, ECP_COPY)
	in.net.bufOut = append(in.net.bufOut, ECP_HOST)
	in.net.bufOut = append(in.net.bufOut, ECP_CALLDATA)
	in.net.bufOut = append(in.net.bufOut, 0)
	// src offset, dest offset, length
	in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, 0)
	in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, 0)
	in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, (uint32)(len(contract.Input)))
	in.net.bufOut = append(in.net.bufOut, contract.Input...)
	in.net.conn.Write(in.net.bufOut)

	// Copy Env
	// op, src, dest, padding
	in.net.bufOut = in.net.bufOut[:2]
	in.net.bufOut = append(in.net.bufOut, ECP_COPY)
	in.net.bufOut = append(in.net.bufOut, ECP_HOST)
	in.net.bufOut = append(in.net.bufOut, ECP_ENV)
	in.net.bufOut = append(in.net.bufOut, 0)
	// src offset, dest offset, length
	in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, 0)
	in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, 0)
	in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, 1024)
	// env data
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 40 blockhash [func call]
	in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, in.evm.Context.Coinbase.Bytes()) // 41 coinbase
	in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, in.evm.Context.Time.Bytes()) // 42 timestamp
	in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, in.evm.Context.BlockNumber.Bytes()) // 43 number
	in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, in.evm.Context.Difficulty.Bytes()) // 44 difficulty
	in.net.bufOut = append256FromUint(in.net.bufOut, in.evm.Context.GasLimit) // 45 gaslimit
	in.net.bufOut = append256FromUint(in.net.bufOut, 2018) // 46 chainid, 2018=dev
	in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, in.evm.StateDB.GetBalance(contract.Address()).Bytes()) // 47 selfbalance
	in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, in.evm.Context.BaseFee.Bytes()) // 48 basefee
	// 58 pc, internal, use 4f
	in.net.bufOut = append256FromUint(in.net.bufOut, 0)// 59 msize, maintained internally
	in.net.bufOut = append256FromUint(in.net.bufOut, contract.Gas) // 5a gas, the initial gas is passed to hardware
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 0b
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 0c
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 0d
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 0e (stack size)
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 0f (pc)

	in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, contract.Address().Bytes()) // 30 address
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 31 balance [func call]
	in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, in.evm.Origin.Bytes()) // 32 origin
	in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, contract.Caller().Bytes()) // 33 caller
	in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, contract.value.Bytes()) // 34 callvalue
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 35 calldataload [func call]
	in.net.bufOut = append256FromUint(in.net.bufOut, uint64(len(contract.Input))) // 36 calldatasize
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 37 calldatacopy [func call]
	in.net.bufOut = append256FromUint(in.net.bufOut, uint64(len(contract.Code))) // 38 codesize
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 39 codecopy [func call]
	in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, in.evm.GasPrice.Bytes()) // 3a gasprice
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 3b extcodesize [func call]
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 3c extcodecopy [func call]
	in.net.bufOut = append256FromUint(in.net.bufOut, uint64(len(in.returnData))) // 3d returndatasize
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 3e returndatacopy [func call]
	in.net.bufOut = append256FromUint(in.net.bufOut, 0) // 3f extcodehash [func call]
	
	in.net.conn.Write(in.net.bufOut)

	// Start
	in.net.bufOut = in.net.bufOut[:2]
	in.net.bufOut = append(in.net.bufOut, ECP_CALL)
	in.net.bufOut = append(in.net.bufOut, ECP_HOST)
	in.net.bufOut = append(in.net.bufOut, ECP_CONTROL)
	in.net.bufOut = append(in.net.bufOut, 0)
	in.net.bufOut = binary.LittleEndian.AppendUint64(in.net.bufOut, pc)
	in.net.conn.Write(in.net.bufOut)
}

// Run loops and evaluates the contract's code with the given input data and returns
// the return byte-slice and an error if one occurred.
//
// It's important to note that any errors returned by the interpreter should be
// considered a revert-and-consume-all-gas operation except for
// ErrExecutionReverted which means revert-and-keep-gas-left.
func (in *EVMInterpreter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	// Increment the call depth which is restricted to 1024
	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// Make sure the readOnly is only set if we aren't in readOnly yet.
	// This also makes sure that the readOnly flag isn't removed for child calls.
	if readOnly && !in.readOnly {
		in.readOnly = true
		defer func() { in.readOnly = false }()
	}

	// Reset the previous call's return data. It's unimportant to preserve the old buffer
	// as every returning call will return new data anyway.
	in.returnData = nil

	// Don't bother with the execution if there's no code.
	if len(contract.Code) == 0 {
		return nil, nil
	}

	// We still need a mem and storage locally
	// because the caches on the FPGA are usually small
	var (
		mem     = NewMemory() // bound memory
		stack   = newstack()  // local stack
		pc			= uint64(0)
		cost    uint64
		callContext = &ScopeContext{
			Memory:   mem,
			Stack:    stack,
			Contract: contract,
		}

		// copies used by tracer
		pcCopy  uint64 // needed for the deferred EVMLogger
		gasCopy uint64 // for EVMLogger to log gas remaining before execution
		logged  bool   // deferred EVMLogger should ignore already logged steps
		res     []byte // result of the opcode execution function
	)
	contract.Input = input

	// Send request to HEVM
	in.loadContextToHardware(callContext, pc)

	// Main loop
	// Deal with incoming requests
	for {
		_, err := in.net.conn.Read(in.net.bufIn)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}

		bufIn := in.net.bufIn[2:]

		opcode := bufIn[0]
		src := bufIn[1]
		// bufIn[2] should always be HOST
		funccode := bufIn[3]  // call mode
		xulu.Use(funccode)

		srcOffset := binary.LittleEndian.Uint32(bufIn[4:8])
		destOffset := binary.LittleEndian.Uint32(bufIn[8:12])
		length := binary.LittleEndian.Uint32(bufIn[12:16])

		// op
		if opcode == ECP_COPY {
			if src == ECP_MEM {
				if srcOffset + length > uint32(mem.Len()) {
					mem.Resize(uint64(srcOffset + length))
				}
				copy(mem.store[srcOffset:], bufIn[16:16+length])
			} else if src == ECP_STORAGE {
				num_of_items := binary.LittleEndian.Uint32(bufIn[16:20])
				storageBase := uint32(20)

				for i := uint32(0); i < num_of_items; i += 1 {
					offset := i * 64
					key := common.BytesToHash(bufIn[storageBase+offset : storageBase+offset+32])
					value := common.BytesToHash(bufIn[storageBase+offset+32 : storageBase+offset+64])
					in.evm.StateDB.SetState(contract.Address(), key, value)
				}
			}
		} else if opcode == ECP_SWAP {
			if src == ECP_MEM {
				if srcOffset + length > uint32(mem.Len()) {
					mem.Resize(uint64(srcOffset + length))
				}
				// copy, then send
				copy(mem.store[srcOffset:], bufIn[16:16+length])
				
				in.net.bufOut = in.net.bufOut[:2]
				in.net.bufOut = append(in.net.bufOut, ECP_COPY)
				in.net.bufOut = append(in.net.bufOut, ECP_HOST)
				in.net.bufOut = append(in.net.bufOut, ECP_MEM)
				in.net.bufOut = append(in.net.bufOut, 0)
				in.net.bufOut = append(in.net.bufOut, mem.store[destOffset])
				in.net.conn.Write(in.net.bufOut)
			} else if src == ECP_STORAGE {
				num_of_items := binary.LittleEndian.Uint32(bufIn[16:20])
				storageBase := uint32(20)
				 
				// copy, then send
				for i := uint32(0); i < num_of_items; i += 1 {
					offset := i * 64
					key := common.BytesToHash(bufIn[storageBase+offset : storageBase+offset+32])
					value := common.BytesToHash(bufIn[storageBase+offset+32 : storageBase+offset+64])
					in.evm.StateDB.SetState(contract.Address(), key, value)
				}
				
				query_base := uint32(20 + num_of_items * 64)
				num_of_items = binary.LittleEndian.Uint32(bufIn[query_base:query_base+4])
				storageBase = query_base + 4

				in.net.bufOut = in.net.bufOut[:2]
				in.net.bufOut = append(in.net.bufOut, ECP_COPY)
				in.net.bufOut = append(in.net.bufOut, ECP_HOST)
				in.net.bufOut = append(in.net.bufOut, ECP_STORAGE)
				in.net.bufOut = append(in.net.bufOut, 0)
				
				in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, 0)
				in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, 0)
				in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, 64 * num_of_items + 4)

				in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, num_of_items)

				for i := uint32(0); i < num_of_items; i += 1 {
					offset := i * 32
					key := common.BytesToHash(bufIn[storageBase+offset : storageBase+offset+32])
					value := in.evm.StateDB.GetState(contract.Address(), key)
					in.net.bufOut = append(in.net.bufOut, key[:]...)
					in.net.bufOut = append(in.net.bufOut, value[:]...)
				}
				in.net.conn.Write(in.net.bufOut)
			}

		} else if opcode == ECP_QUERY {
			// answer query with address param

			param := bufIn[16:48]
			address := common.BytesToAddress(swapEndian(param[0:20]))

			if funccode == ECP_QUERY_EXTCODECOPY {
				in.net.bufOut = in.net.bufOut[:2]
				in.net.bufOut = append(in.net.bufOut, ECP_COPY)
				in.net.bufOut = append(in.net.bufOut, ECP_HOST)
				in.net.bufOut = append(in.net.bufOut, ECP_MEM)
				in.net.bufOut = append(in.net.bufOut, 0)
				
				in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, srcOffset)
				in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, destOffset)
				in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, length)
				in.net.bufOut = append(in.net.bufOut, in.evm.StateDB.GetCodeHash(contract.Address()).Bytes()...)
				in.net.conn.Write(in.net.bufOut)
			} else {
				in.net.bufOut = in.net.bufOut[:2]
				in.net.bufOut = append(in.net.bufOut, ECP_COPY)
				in.net.bufOut = append(in.net.bufOut, ECP_HOST)
				in.net.bufOut = append(in.net.bufOut, ECP_STACK)
				in.net.bufOut = append(in.net.bufOut, 0)
				
				in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, 0)
				in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, 0x8000)   // copy to stack data buffer
				in.net.bufOut = binary.LittleEndian.AppendUint32(in.net.bufOut, 32 + 1)   // copy 32 bytes of data + 1 byte of write enable

				if funccode == ECP_QUERY_BALANCE {
					in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, in.evm.StateDB.GetBalance(address).Bytes())
				}  else if funccode == ECP_QUERY_EXTCODEHASH {
					in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, in.evm.StateDB.GetCodeHash(address).Bytes())
				} else if funccode == ECP_QUERY_EXTCODESIZE {
					in.net.bufOut = append256FromUint(in.net.bufOut, uint64(in.evm.StateDB.GetCodeSize(address)))
				} else if funccode == ECP_QUERY_BLOCKHASH { 
					in.net.bufOut = append256FromBigEndianBytes(in.net.bufOut, in.evm.Context.GetHash(binary.LittleEndian.Uint64(param[0:8])).Bytes())
				}
				in.net.bufOut = append(in.net.bufOut, 1)
			}

		} else if opcode == ECP_END {
			// The hardware should copy all local storage to host before calling END

			// TODO: return type (stop, return, revert)
			if (funccode == ECP_END_STOP) {
				// stop
				// do nothing
			} else if (funccode == ECP_END_RETURN) {
				// return
				// copy return data to host
				res = bufIn[16:16+length]
			} else if (funccode == ECP_END_REVERT) {
				// revert
				res = bufIn[16:16+length]
				err = ErrExecutionReverted
			} else {
				// selfdestruct
				// TODO
			}

			break
		} else if opcode == ECP_CALL {
			// execute *_CALL instructions
			// not fully implemented

			// need to sync before call
			// mem, stack, (storage?)
			// carried as payload
			// pc, cost, Contract.gas

			pc = binary.LittleEndian.Uint64(bufIn[16:24])
			cost = binary.LittleEndian.Uint64(bufIn[24:32])
			contract.Gas = binary.LittleEndian.Uint64(bufIn[32:48])
			
			var err error = nil
			if funccode == ECP_CALL_CREATE {
				res, err = opCreate(&pc, in, callContext)
			} else if funccode == ECP_CALL_CALL {
				res, err = opCall(&pc, in, callContext)
			} else if funccode == ECP_CALL_CALLCODE {
				res, err = opCallCode(&pc, in, callContext)
			}	else if funccode == ECP_CALL_DELEGATECALL {
				res, err = opDelegateCall(&pc, in, callContext)
			} else if funccode == ECP_CALL_CREATE2 {
				res, err = opCreate2(&pc, in, callContext)
			} else if funccode == ECP_CALL_STATICCALL {
				res, err = opStaticCall(&pc, in, callContext)
			}

			if err != nil {
				break
			}

			// TODO: recover stack, mem, env
			// and resume
			in.loadContextToHardware(callContext, pc)

		} else if opcode == ECP_DEBUG {
			pc := binary.LittleEndian.Uint32(bufIn[16:20])
			gas := binary.LittleEndian.Uint64(bufIn[20:28])
			stackSize := binary.LittleEndian.Uint32(bufIn[28:32])
			fmt.Printf("pc: %d, gas: %d\nstack <top %d>:\n", pc, gas, stackSize)
			
			for i := uint32(0); i < stackSize; i += 1 {
				offset := i * 32 + 32
				fmt.Printf("  %d: %v\n", i, newUint256FromLittleEndianBytes(bufIn[offset:offset+32]).Hex())
			}
		}
	}

	if err == errStopToken {
		err = nil // clear stop token error
	}

	xulu.Use(mem, cost, pcCopy, gasCopy, logged)

	return res, err
}
