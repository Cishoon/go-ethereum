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
	"github.com/ethereum/go-ethereum/common"
)

// 配置RegulatoryContract合约地址的公共接口
func ConfigureRegulatoryContract(address string) error {
	addr := common.HexToAddress(address)
	SetRegulatoryContractAddress(addr)
	return nil
}

// 获取当前RegulatoryContract配置状态
func GetRegulatoryContractInfo() (address string, enabled bool) {
	return GetRegulatoryContractStatus()
}

// 启用/禁用监管功能
func SetRegulatoryEnabled(enabled bool) {
	if enabled && regulatoryConfig.address == (common.Address{}) {
		// 如果没有设置地址但要启用，使用默认地址
		regulatoryConfig.address = common.HexToAddress(DefaultRegulatoryContractAddress)
	}
	regulatoryConfig.enabled = enabled
}

// 检查监管功能是否启用
func IsRegulatoryEnabled() bool {
	return regulatoryConfig.enabled
}