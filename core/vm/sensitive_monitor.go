// Copyright 2024 The go-ethereum Authors
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
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

// 敏感函数签名列表 - 仅包含直接转账函数
var sensitiveFunctionSignatures = map[string]string{
	// ERC-20 转账函数
	"a9059cbb": "transfer(address,uint256)",
	"23b872dd": "transferFrom(address,address,uint256)",
	
	// ERC-721 转账函数
	"42842e0e": "safeTransferFrom(address,address,uint256)",
	"b88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
	
	// 批量转账函数 (需要根据实际合约计算函数选择器)
	// "batchTransfer": "batchTransfer(address[],uint256[])",
}

// 检查函数签名是否为敏感函数
func isSensitiveFunction(input []byte) (bool, string) {
	if len(input) < 4 {
		return false, ""
	}
	
	// 提取函数选择器 (前4字节)
	selector := fmt.Sprintf("%x", input[:4])
	
	if funcName, exists := sensitiveFunctionSignatures[selector]; exists {
		return true, funcName
	}
	
	return false, selector // 返回函数选择器而不是空字符串
}

// StringTracker合约配置
var stringTrackerConfig = struct {
	address   common.Address
	enabled   bool
}{
	// StringTracker合约地址
	address: common.HexToAddress("0x319b4b3b71398EABaDae47ccEA2e1e6be3e83056"), // 您的StringTracker合约地址
	enabled: true, // 启用StringTracker记录
}

// 设置StringTracker合约地址
func SetStringTrackerAddress(addr common.Address) {
	stringTrackerConfig.address = addr
	stringTrackerConfig.enabled = addr != (common.Address{})
}

// updateString函数的函数选择器: updateString(string)
// 动态计算正确的函数选择器
func getUpdateStringSelector() []byte {
	selector := crypto.Keccak256([]byte("updateString(string)"))[:4]
	fmt.Printf("[调试] 计算的updateString函数选择器: 0x%x\n", selector)
	return selector
}

// 构造StringTracker合约调用数据
func buildStringTrackerCallData(sensitiveData string) []byte {
	// updateString(string memory _newValue)
	// 函数选择器 + ABI编码的字符串参数
	
	// 字符串的ABI编码:
	// - 偏移量 (32字节): 0x20 (表示字符串数据从第32字节开始)
	// - 字符串长度 (32字节)
	// - 字符串数据 (补齐到32字节的倍数)
	
	data := make([]byte, 0)
	
	// 1. 函数选择器
	selector := getUpdateStringSelector()
	data = append(data, selector...)
	
	// 2. 偏移量 (0x20 = 32)
	offset := make([]byte, 32)
	offset[31] = 0x20
	data = append(data, offset...)
	
	// 3. 字符串长度
	strBytes := []byte(sensitiveData)
	strLen := make([]byte, 32)
	strLenBig := big.NewInt(int64(len(strBytes)))
	strLenBig.FillBytes(strLen)
	data = append(data, strLen...)
	
	// 4. 字符串数据 (补齐到32字节的倍数)
	paddedStr := make([]byte, ((len(strBytes)+31)/32)*32)
	copy(paddedStr, strBytes)
	data = append(data, paddedStr...)
	
	return data
}

// 调用StringTracker合约记录敏感操作
func callStringTracker(evm *EVM, caller common.Address, sensitiveData string) error {
	if !stringTrackerConfig.enabled {
		fmt.Printf("[StringTracker] 功能未启用\n")
		return nil
	}
	
	fmt.Printf("[StringTracker调试] 开始调用合约: %s\n", stringTrackerConfig.address.Hex())
	fmt.Printf("[StringTracker调试] 调用者: %s\n", caller.Hex())
	fmt.Printf("[StringTracker调试] 数据: %s\n", sensitiveData)
	
	// 构造调用数据
	callData := buildStringTrackerCallData(sensitiveData)
	fmt.Printf("[StringTracker调试] 调用数据: 0x%x\n", callData)
	fmt.Printf("[StringTracker调试] 调用数据长度: %d bytes\n", len(callData))
	
	// 调用StringTracker合约
	ret, leftOverGas, err := evm.Call(
		caller,                        // 调用者
		stringTrackerConfig.address,   // StringTracker合约地址
		callData,                      // 调用数据
		300000,                        // gas限制 (增加到300k)
		uint256.NewInt(0),            // value (0 ETH)
	)
	
	fmt.Printf("[StringTracker调试] 返回数据: 0x%x\n", ret)
	fmt.Printf("[StringTracker调试] 剩余Gas: %d\n", leftOverGas)
	
	if err != nil {
		fmt.Printf("[StringTracker错误] 调用失败: %v\n", err)
		return err
	}
	
	fmt.Printf("[StringTracker成功] 已记录敏感操作到合约: %s\n", stringTrackerConfig.address.Hex())
	return nil
}

// 解析转账函数参数
func parseTransferParams(input []byte, funcName string) map[string]interface{} {
	params := make(map[string]interface{})
	
	if len(input) < 4 {
		return params
	}
	
	data := input[4:] // 跳过函数选择器
	
	switch funcName {
	case "transfer(address,uint256)":
		if len(data) >= 64 {
			// 第一个参数：to 地址 (32字节，取后20字节)
			to := common.BytesToAddress(data[12:32])
			// 第二个参数：amount (32字节)
			amount := new(big.Int).SetBytes(data[32:64])
			params["to"] = to.Hex()
			params["amount"] = amount.String()
		}
	case "transferFrom(address,address,uint256)":
		if len(data) >= 96 {
			// 第一个参数：from 地址
			from := common.BytesToAddress(data[12:32])
			// 第二个参数：to 地址
			to := common.BytesToAddress(data[44:64])
			// 第三个参数：amount
			amount := new(big.Int).SetBytes(data[64:96])
			params["from"] = from.Hex()
			params["to"] = to.Hex()
			params["amount"] = amount.String()
		}
	case "safeTransferFrom(address,address,uint256)", "safeTransferFrom(address,address,uint256,bytes)":
		if len(data) >= 96 {
			// NFT 转账参数
			from := common.BytesToAddress(data[12:32])
			to := common.BytesToAddress(data[44:64])
			tokenId := new(big.Int).SetBytes(data[64:96])
			params["from"] = from.Hex()
			params["to"] = to.Hex()
			params["tokenId"] = tokenId.String()
		}
	}
	
	return params
}

// 敏感函数监控 - 在控制台输出检测到的敏感操作并调用StringTracker合约
func monitorSensitiveCall(caller common.Address, target common.Address, input []byte, funcName string, evm *EVM) {
	params := parseTransferParams(input, funcName)
	
	fmt.Printf("========================================\n")
	fmt.Printf("[敏感操作监控] 检测到敏感函数调用\n")
	fmt.Printf("========================================\n")
	fmt.Printf("函数名称: %s\n", funcName)
	fmt.Printf("调用者地址: %s\n", caller.Hex())
	fmt.Printf("目标合约: %s\n", target.Hex())
	fmt.Printf("函数选择器: 0x%x\n", input[:4])
	
	if len(params) > 0 {
		fmt.Printf("函数参数:\n")
		for key, value := range params {
			fmt.Printf("  %s: %v\n", key, value)
		}
	}
	
	fmt.Printf("原始输入数据: 0x%x\n", input)
	fmt.Printf("数据长度: %d bytes\n", len(input))
	fmt.Printf("========================================\n\n")
	
	// 构造敏感操作记录字符串
	recordData := fmt.Sprintf("敏感函数调用: %s | 调用者: %s | 目标: %s | 参数: %v", 
		funcName, caller.Hex(), target.Hex(), params)
	
	// 调用StringTracker合约记录
	if err := callStringTracker(evm, caller, recordData); err != nil {
		fmt.Printf("[警告] StringTracker调用失败: %v\n", err)
	}
}