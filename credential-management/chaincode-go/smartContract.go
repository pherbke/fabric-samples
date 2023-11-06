/*
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	cuckooSmartContract, err := contractapi.NewChaincode(&cuckoofilter.SmartContract{})
	if err != nil {
		log.Panicf("Error creating cuckoo filter chaincode: %v", err)
	}

	if err := cuckooSmartContract.Start(); err != nil {
		log.Panicf("Error starting cuckoo filter chaincode: %v", err)
	}
}
