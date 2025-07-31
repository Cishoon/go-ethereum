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
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

// RegulatoryContract配置
var regulatoryConfig = struct {
	address common.Address
	enabled bool
}{
	// RegulatoryContract合约地址
	address: common.HexToAddress("0x5B8f4B0d72abB8eAfDf1bb5133902AA801c5A696"),
	enabled: true,
}

// ABI函数选择器定义
var (
	// isWhitelisted(address) -> bool
	isWhitelistedSelector = crypto.Keccak256([]byte("isWhitelisted(address)"))[:4]
	
	// isSensitiveFunction(address,bytes4) -> (bool,string)
	isSensitiveFunctionSelector = crypto.Keccak256([]byte("isSensitiveFunction(address,bytes4)"))[:4]
	
	// calculateRiskScore(address,address) -> uint256
	calculateRiskScoreSelector = crypto.Keccak256([]byte("calculateRiskScore(address,address)"))[:4]
)

// 解析规则结构体
type ParseRule struct {
	From   string `json:"from"`   // "msg.sender" 或 "param[0]"
	To     string `json:"to"`     // "param[0]" 或 "param[1]"
	Amount string `json:"amount"` // "param[1]" 或 "param[2]"
	Type   string `json:"type"`   // "transfer" 或 "approval"
}

// 交易信息结构体
type TransactionInfo struct {
	From   common.Address
	To     common.Address
	Amount *big.Int
	Type   string
}

// 设置RegulatoryContract地址
func SetRegulatoryContractAddress(addr common.Address) {
	regulatoryConfig.address = addr
	regulatoryConfig.enabled = addr != (common.Address{})
}

// 获取RegulatoryContract配置状态
func GetRegulatoryContractStatus() (address string, enabled bool) {
	return regulatoryConfig.address.Hex(), regulatoryConfig.enabled
}

// 构造合约查询调用数据
func buildContractCallData(selector []byte, params ...[]byte) []byte {
	data := make([]byte, 0)
	data = append(data, selector...)
	
	for _, param := range params {
		paddedParam := make([]byte, 32)
		copy(paddedParam[32-len(param):], param)
		data = append(data, paddedParam...)
	}
	
	return data
}

// 检查合约是否在白名单中
func checkWhitelist(evm *EVM, contractAddr common.Address) (bool, error) {
	if !regulatoryConfig.enabled {
		return true, nil // 监管功能禁用时默认放行
	}
	
	// 构造 isWhitelisted(address) 调用数据
	callData := buildContractCallData(isWhitelistedSelector, contractAddr.Bytes())
	
	// 调用监管合约
	ret, _, err := evm.StaticCall(
		common.Address{}, // 系统调用
		regulatoryConfig.address,
		callData,
		100000, // gas限制
	)
	
	if err != nil {
		fmt.Printf("[监管错误] 白名单查询失败: %v\n", err)
		return false, err
	}
	
	// 解析返回值 (bool)
	if len(ret) >= 32 {
		result := new(big.Int).SetBytes(ret[:32])
		isWhitelisted := result.Cmp(big.NewInt(0)) != 0
		
		fmt.Printf("[监管检查] 合约 %s 白名单状态: %t\n", contractAddr.Hex(), isWhitelisted)
		return isWhitelisted, nil
	}
	
	return false, fmt.Errorf("invalid response from regulatory contract")
}

// 检查函数是否为敏感函数并获取解析规则
func checkSensitiveFunction(evm *EVM, contractAddr common.Address, selector []byte) (bool, string, error) {
	if !regulatoryConfig.enabled {
		return false, "", nil
	}
	
	// 构造 isSensitiveFunction(address,bytes4) 调用数据
	selectorPadded := make([]byte, 32)
	copy(selectorPadded[28:], selector) // bytes4放在最后4位
	
	callData := buildContractCallData(isSensitiveFunctionSelector, contractAddr.Bytes(), selectorPadded)
	
	// 调用监管合约
	ret, _, err := evm.StaticCall(
		common.Address{}, // 系统调用
		regulatoryConfig.address,
		callData,
		150000, // gas限制
	)
	
	if err != nil {
		fmt.Printf("[监管错误] 敏感函数查询失败: %v\n", err)
		return false, "", err
	}
	
	if len(ret) < 64 {
		return false, "", fmt.Errorf("invalid response length")
	}
	
	// 解析返回值 (bool, string)
	isSensitive := new(big.Int).SetBytes(ret[:32]).Cmp(big.NewInt(0)) != 0
	
	if !isSensitive {
		return false, "", nil
	}
	
	// 解析字符串偏移量和长度
	stringOffset := new(big.Int).SetBytes(ret[32:64]).Uint64()
	if stringOffset+32 > uint64(len(ret)) {
		return false, "", fmt.Errorf("string offset out of bounds")
	}
	
	stringLength := new(big.Int).SetBytes(ret[stringOffset:stringOffset+32]).Uint64()
	if stringOffset+32+stringLength > uint64(len(ret)) {
		return false, "", fmt.Errorf("string length out of bounds")
	}
	
	parseRule := string(ret[stringOffset+32 : stringOffset+32+stringLength])
	
	fmt.Printf("[监管检查] 函数 %x 敏感状态: %t, 解析规则: %s\n", selector, isSensitive, parseRule)
	return isSensitive, parseRule, nil
}

// 解析交易参数
func parseTransactionParams(caller common.Address, input []byte, parseRuleStr string) (*TransactionInfo, error) {
	var rule ParseRule
	if err := json.Unmarshal([]byte(parseRuleStr), &rule); err != nil {
		return nil, fmt.Errorf("failed to parse rule: %v", err)
	}
	
	txInfo := &TransactionInfo{
		Type: rule.Type,
	}
	
	// 解析发送方
	if rule.From == "msg.sender" {
		txInfo.From = caller
	} else if strings.HasPrefix(rule.From, "param[") {
		// 解析参数索引 param[0], param[1], etc.
		paramIndex := parseParamIndex(rule.From)
		if addr := extractAddressParam(input, paramIndex); addr != nil {
			txInfo.From = *addr
		}
	}
	
	// 解析接收方
	if strings.HasPrefix(rule.To, "param[") {
		paramIndex := parseParamIndex(rule.To)
		if addr := extractAddressParam(input, paramIndex); addr != nil {
			txInfo.To = *addr
		}
	}
	
	// 解析金额
	if strings.HasPrefix(rule.Amount, "param[") {
		paramIndex := parseParamIndex(rule.Amount)
		if amount := extractUint256Param(input, paramIndex); amount != nil {
			txInfo.Amount = amount
		}
	}
	
	return txInfo, nil
}

// 解析参数索引 "param[1]" -> 1
func parseParamIndex(paramStr string) int {
	if len(paramStr) >= 7 && paramStr[:6] == "param[" && paramStr[len(paramStr)-1] == ']' {
		indexStr := paramStr[6 : len(paramStr)-1]
		if indexStr == "0" {
			return 0
		} else if indexStr == "1" {
			return 1
		} else if indexStr == "2" {
			return 2
		}
	}
	return -1
}

// 从input中提取地址参数
func extractAddressParam(input []byte, paramIndex int) *common.Address {
	if paramIndex < 0 || len(input) < 4+(paramIndex+1)*32 {
		return nil
	}
	
	offset := 4 + paramIndex*32
	addrBytes := input[offset+12 : offset+32] // 地址占后20字节
	addr := common.BytesToAddress(addrBytes)
	return &addr
}

// 从input中提取uint256参数
func extractUint256Param(input []byte, paramIndex int) *big.Int {
	if paramIndex < 0 || len(input) < 4+(paramIndex+1)*32 {
		return nil
	}
	
	offset := 4 + paramIndex*32
	return new(big.Int).SetBytes(input[offset : offset+32])
}

// 执行风险传播计算
func executeRiskPropagation(evm *EVM, sender, receiver common.Address) error {
	if !regulatoryConfig.enabled || sender == receiver {
		return nil
	}
	
	// 构造 calculateRiskScore(address,address) 调用数据
	callData := buildContractCallData(calculateRiskScoreSelector, sender.Bytes(), receiver.Bytes())
	
	// 调用监管合约
	ret, _, err := evm.Call(
		common.Address{}, // 系统调用
		regulatoryConfig.address,
		callData,
		200000, // gas限制
		uint256.NewInt(0),
	)
	
	if err != nil {
		fmt.Printf("[风险传播错误] 计算失败: %v\n", err)
		return err
	}
	
	// 解析返回的新风险评分
	if len(ret) >= 32 {
		newScore := new(big.Int).SetBytes(ret[:32])
		fmt.Printf("[风险传播] %s -> %s, 新评分: %s\n", 
			sender.Hex(), receiver.Hex(), newScore.String())
	}
	
	return nil
}

// 主要的监管检查函数
func performRegulatoryCheck(evm *EVM, caller, target common.Address, input []byte) error {
	// 避免对监管合约自身的调用进行检查，防止无限递归
	if target == regulatoryConfig.address {
		return nil
	}
	
	if !regulatoryConfig.enabled || len(input) < 4 {
		return nil
	}
	
	fmt.Printf("[监管系统] 开始检查调用: %s -> %s\n", caller.Hex(), target.Hex())
	
	// 第一步：检查白名单
	isWhitelisted, err := checkWhitelist(evm, target)
	if err != nil {
		return fmt.Errorf("whitelist check failed: %v", err)
	}
	
	if !isWhitelisted {
		return fmt.Errorf("contract %s is not whitelisted", target.Hex())
	}
	
	// 第二步：检查敏感函数
	selector := input[:4]
	isSensitive, parseRule, err := checkSensitiveFunction(evm, target, selector)
	if err != nil {
		return fmt.Errorf("sensitive function check failed: %v", err)
	}
	
	if !isSensitive {
		fmt.Printf("[监管系统] 非敏感函数，直接放行\n")
		return nil
	}
	
	// 第三步：解析参数并执行风险传播
	txInfo, err := parseTransactionParams(caller, input, parseRule)
	if err != nil {
		return fmt.Errorf("failed to parse transaction parameters: %v", err)
	}
	
	fmt.Printf("[监管系统] 敏感操作检测: %s -> %s, 金额: %s\n", 
		txInfo.From.Hex(), txInfo.To.Hex(), txInfo.Amount.String())
	
	// 执行风险传播
	if err := executeRiskPropagation(evm, txInfo.From, txInfo.To); err != nil {
		fmt.Printf("[监管警告] 风险传播失败: %v\n", err)
		// 风险传播失败不阻止交易，只记录警告
	}
	
	fmt.Printf("[监管系统] 检查完成，允许执行\n")
	return nil
}