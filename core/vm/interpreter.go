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
	ECP_NONE byte = 0
	ECP_CALL      = 1
	ECP_COPY      = 2
	ECP_SWAP      = 3
	ECP_END       = 4
	ECP_DEBUG			= 5
)

const (
	ECP_CONTROL  byte = 0
	ECP_CODE          = 1
	ECP_CALLDATA      = 2
	ECP_MEM           = 3
	ECP_STORAGE       = 4
	ECP_HOST          = 5
	ECP_ENV						= 6
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

// EVMInterpreter represents an EVM interpreter
type EVMInterpreter struct {
	evm *EVM
	cfg Config

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
	}
}

func append256FromUint(buf []byte, val uint64) []byte {
	var tmp [32]byte
	binary.LittleEndian.PutUint64(tmp[:8], val)
	return append(buf, tmp[:]...)
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
		mem         = NewMemory() // bound memory
		cost    int64

		// copies used by tracer
		pcCopy  uint64 // needed for the deferred EVMLogger
		gasCopy uint64 // for EVMLogger to log gas remaining before execution
		logged  bool   // deferred EVMLogger should ignore already logged steps
		res     []byte // result of the opcode execution function
	)
	contract.Input = input

	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:23334")
	raddr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 23333}
	conn, err := net.DialUDP("udp", laddr, &raddr)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer conn.Close()

	buf   := make([]byte, 0, 2048)
	bufIn := make([]byte, 2048, 2048)

	// Send request to HEVM

	// Copy Code
	// op, src, dest, padding
	buf = append(buf, ECP_COPY)
	buf = append(buf, ECP_HOST)
	buf = append(buf, ECP_CODE)
	buf = append(buf, 0)
	// src offset, dest offset, length
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, (uint32)(len(contract.Code)))
	buf = append(buf, contract.Code...)
	conn.Write(buf)

	// Copy Input
	// op, src, dest, padding
	buf = buf[:0]
	buf = append(buf, ECP_COPY)
	buf = append(buf, ECP_HOST)
	buf = append(buf, ECP_CALLDATA)
	buf = append(buf, 0)
	// src offset, dest offset, length
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, (uint32)(len(contract.Input)))
	buf = append(buf, contract.Input...)
	conn.Write(buf)

	// Copy Env
	// op, src, dest, padding
	buf = buf[:0]
	buf = append(buf, ECP_COPY)
	buf = append(buf, ECP_HOST)
	buf = append(buf, ECP_ENV)
	buf = append(buf, 0)
	// src offset, dest offset, length
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, 32)
	// env data
	buf = append256FromUint(buf, 0) // 40 blockhash [func call]
	buf = append256FromBigEndianBytes(buf, in.evm.Context.Coinbase.Bytes()) // 41 coinbase
	buf = append256FromBigEndianBytes(buf, in.evm.Context.Time.Bytes()) // 42 timestamp
	buf = append256FromBigEndianBytes(buf, in.evm.Context.BlockNumber.Bytes()) // 43 number
	buf = append256FromBigEndianBytes(buf, in.evm.Context.Difficulty.Bytes()) // 44 difficulty
	buf = append256FromUint(buf, in.evm.Context.GasLimit) // 45 gaslimit
	buf = append256FromUint(buf, 2018) // 46 chainid, 2018=dev
	buf = append256FromBigEndianBytes(buf, in.evm.StateDB.GetBalance(contract.Address()).Bytes()) // 47 selfbalance
	buf = append256FromBigEndianBytes(buf, in.evm.Context.BaseFee.Bytes()) // 48 basefee
	// 58 pc, internal, use 4f
	buf = append256FromUint(buf, 0)// 59 msize, maintained internally
	buf = append256FromUint(buf, contract.Gas) // 5a gas, the initial gas is passed to hardware
	buf = append256FromUint(buf, 0) // 0b
	buf = append256FromUint(buf, 0) // 0c
	buf = append256FromUint(buf, 0) // 0d
	buf = append256FromUint(buf, 0) // 0e
	buf = append256FromUint(buf, 0) // 0f

	buf = append256FromBigEndianBytes(buf, contract.Address().Bytes()) // 30 address
	buf = append256FromUint(buf, 0) // 31 balance [func call]
	buf = append256FromBigEndianBytes(buf, in.evm.Origin.Bytes()) // 32 origin
	buf = append256FromBigEndianBytes(buf, contract.Caller().Bytes()) // 33 caller
	buf = append256FromBigEndianBytes(buf, contract.value.Bytes()) // 34 callvalue
	buf = append256FromUint(buf, 0) // 35 calldataload [func call]
	buf = append256FromUint(buf, uint64(len(contract.Input))) // 36 calldatasize
	buf = append256FromUint(buf, 0) // 37 calldatacopy [func call]
	buf = append256FromUint(buf, uint64(len(contract.Code))) // 38 codesize
	buf = append256FromUint(buf, 0) // 39 codecopy [func call]
	buf = append256FromBigEndianBytes(buf, in.evm.GasPrice.Bytes()) // 3a gasprice
	buf = append256FromUint(buf, 0) // 3b extcodesize [func call]
	buf = append256FromUint(buf, 0) // 3c extcodecopy [func call]
	buf = append256FromUint(buf, uint64(len(in.returnData))) // 3d returndatasize
	buf = append256FromUint(buf, 0) // 3e returndatacopy [func call]
	buf = append256FromUint(buf, 0) // 3f extcodehash [func call]
	
	conn.Write(buf)

	// Start
	buf = buf[:0]
	buf = append(buf, ECP_CALL)
	buf = append(buf, ECP_HOST)
	buf = append(buf, ECP_CONTROL)
	buf = append(buf, 0)
	conn.Write(buf)

	// Main loop
	// Deal with incoming requests
	for {
		_, err := conn.Read(bufIn)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}

		opcode := bufIn[0]
		src := bufIn[1]

		srcOffset := binary.LittleEndian.Uint32(bufIn[4:8])
		destOffset := binary.LittleEndian.Uint32(bufIn[8:12])
		length := binary.LittleEndian.Uint32(bufIn[12:16])

		// TODO: Parse request
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
					offset := i * 16
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
				
				buf = buf[:0]
				buf = append(buf, ECP_COPY)
				buf = append(buf, ECP_HOST)
				buf = append(buf, ECP_MEM)
				buf = append(buf, 0)
				buf = append(buf, mem.store[destOffset])
				conn.Write(buf)
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

				buf = buf[:0]
				buf = append(buf, ECP_COPY)
				buf = append(buf, ECP_HOST)
				buf = append(buf, ECP_STORAGE)
				buf = append(buf, 0)
				
				buf = binary.LittleEndian.AppendUint32(buf, 0)
				buf = binary.LittleEndian.AppendUint32(buf, 0)
				buf = binary.LittleEndian.AppendUint32(buf, 32 * num_of_items + 4)

				buf = binary.LittleEndian.AppendUint32(buf, num_of_items)

				for i := uint32(0); i < num_of_items; i += 1 {
					offset := i * 32
					key := common.BytesToHash(bufIn[storageBase+offset : storageBase+offset+32])
					value := in.evm.StateDB.GetState(contract.Address(), key)
					buf = append(buf, key[:]...)
					buf = append(buf, value[:]...)
				}
				conn.Write(buf)
			}

		} else if opcode == ECP_END {
			// The hardware should copy all local storage to host before calling END
			break;
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
