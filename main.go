// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
	// "github.com/ethereum/go-ethereum/abi"
	// "math/big"
	// "github.com/ethereum/go-ethereum/common"
)

type CallResult struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  string `json:"result"`
}

type Status struct {
	Entropy    []byte
	Difficulty *big.Int
}

func getGemStatus() (Status, error) {
	url := "https://rpcapi.fantom.network"
	method := "POST"

	payload := strings.NewReader(`{
	  "jsonrpc": "2.0",
	  "id": 20,
	  "method": "eth_call",
	  "params": [
		  {
			  "from": "0x0000000000000000000000000000000000000000",
			  "data": "0xa1f0406d0000000000000000000000000000000000000000000000000000000000000003",
			  "to": "0x342ebf0a5cec4404ccff73a40f9c30288fc72611"
		  },
		  "latest"
	  ]
  }`)

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		return Status{}, err
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return Status{}, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return Status{}, err
	}

	var cr CallResult
	err = json.Unmarshal(body, &cr)
	if err != nil {
		return Status{}, err
	}

	tmp := cr.Result[128+2:]
	status := Status{}
	status.Entropy, err = hex.DecodeString(tmp[:64])
	if err != nil {
		return Status{}, err
	}
	status.Difficulty = big.NewInt(0)
	status.Difficulty.SetString(tmp[64:128], 16)

	return status, nil
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func getVal(maxInt *big.Int, data []byte, status Status) {
	salt, _ := randomHex(30)
	saltBytes, _ := hex.DecodeString(fmt.Sprintf("%064s", salt))

	saltInt := big.NewInt(0)
	saltInt.SetBytes(saltBytes)

	hash := sha3.NewKeccak256()
	hash.Write(append(data, saltBytes...))
	luck := hash.Sum(nil)

	fmt.Println(hex.EncodeToString(append(data, saltBytes...)))
	fmt.Println("saltInt -> ", saltInt)

	val := big.NewInt(0)
	val.SetBytes(luck)

	dv := new(big.Int).Div(maxInt, status.Difficulty)

	fmt.Println("val luck -> ", val)

	if val.Cmp(dv) < 1 {
		fmt.Println("saltInt -> ", saltInt)
		fmt.Println("val luck -> ", val)
		fmt.Println("is success -> ", val.Cmp(dv) < 1)
	}
}

func main() {

	maxInt := new(big.Int)
	maxInt.SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)

	chainID, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000fa")
	contractAddress, _ := hex.DecodeString("342ebf0a5cec4404ccff73a40f9c30288fc72611")
	senderAddress, _ := hex.DecodeString("498968c2b945ac37b78414f66167b0786e522636")
	moonstoneID, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000003")
	nonce, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	status, err := getGemStatus()
	if err != nil {
		fmt.Println(err)
		return
	}

	data := []byte{}
	data = append(data, chainID...)
	data = append(data, status.Entropy...)
	data = append(data, contractAddress...)
	data = append(data, senderAddress...)
	data = append(data, moonstoneID...)
	data = append(data, nonce...)

	getVal(maxInt, data, status)

	if 0 == 0 {
		return
	}

	n := 16

	current := time.Now().UnixNano()
	var wg sync.WaitGroup
	i := 0
	for -1 < i {
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				getVal(maxInt, data, status)
				wg.Done()
			}()
		}
		wg.Wait()
		i += n
		if i&65535 == 0 {
			fmt.Printf("\riteration %d , time : %d", i, time.Now().UnixNano()-current)
			current = time.Now().UnixNano()
		}
	}

	fmt.Println("Finished")
}
