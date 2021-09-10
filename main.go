package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto/sha3"
)

type CallResult struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  string `json:"result"`
}

type Status struct {
	ChainID         []byte
	ContractAddress []byte
	SenderAddress   []byte
	StoneID         []byte
	Nonce           []byte
	Entropy         []byte
	Difficulty      *big.Int
	MaxInt          *big.Int
	mutex           *sync.RWMutex
}

const URL = "https://rpcapi.fantom.network"
const CONTRACT_ADDRESS = "342ebf0a5cec4404ccff73a40f9c30288fc72611"
const SENDER_ADDRESS = "498968c2b945ac37b78414f66167b0786e522636"
const STONE_ID = "0000000000000000000000000000000000000000000000000000000000000001"
const GET_STATUS_PAYLOAD_TEMPLATE = `{
	"jsonrpc": "2.0",
	"id": 20,
	"method": "eth_call",
	"params": [
		{
			"from": "0x0000000000000000000000000000000000000000",
			"data": "0xa1f0406d$",
			"to": "0xß"
		},
		"latest"
	]
}`

const GET_NONCE_PAYLOAD_TEMPLATE = `{
    "jsonrpc": "2.0",
    "id": 30,
    "method": "eth_call",
    "params": [
        {
            "from": "0x0000000000000000000000000000000000000000",
            "data": "0x70ae92d2000000000000000000000000@",
            "to": "0xß"
        },
        "latest"
    ]
}`

func NewStatus() *Status {
	maxInt := new(big.Int)
	maxInt.SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)
	chainID, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000fa")
	initialNonce, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	contractAddress, _ := hex.DecodeString(CONTRACT_ADDRESS)
	senderAddress, _ := hex.DecodeString(SENDER_ADDRESS)
	stoneID, _ := hex.DecodeString(STONE_ID)

	status := &Status{
		mutex:           new(sync.RWMutex),
		ChainID:         chainID,
		ContractAddress: contractAddress,
		SenderAddress:   senderAddress,
		StoneID:         stoneID,
		Nonce:           initialNonce,
		Entropy:         []byte{},
		MaxInt:          maxInt,
		Difficulty:      big.NewInt(0),
	}

	return status
}

func (s *Status) GetData() []byte {
	s.mutex.RLock()
	defer func() {
		s.mutex.RUnlock()
	}()

	data := []byte{}
	data = append(data, s.ChainID...)
	data = append(data, s.Entropy...)
	data = append(data, s.ContractAddress...)
	data = append(data, s.SenderAddress...)
	data = append(data, s.StoneID...)
	data = append(data, s.Nonce...)

	return data
}

func (s *Status) GetDifficulty() *big.Int {
	s.mutex.RLock()
	defer func() {
		s.mutex.RUnlock()
	}()
	return s.Difficulty
}

func (s *Status) SetNED(nonceBytes []byte, entropyBytes []byte, difficultyBytes []byte) {
	s.mutex.Lock()
	defer func() {
		s.mutex.Unlock()
	}()

	s.Nonce = nonceBytes[:]
	s.Entropy = entropyBytes[:]
	s.Difficulty = big.NewInt(0).SetBytes(difficultyBytes[:])
}

func callContract(payload string) (CallResult, error) {
	client := &http.Client{}
	req, err := http.NewRequest("POST", URL, strings.NewReader(payload))
	if err != nil {
		fmt.Println("call contract error 1. 💥")
		return CallResult{}, err
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println("call contract error 2. 💥")
		return CallResult{}, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("call contract error 3. 💥")
		return CallResult{}, err
	}

	var cr CallResult
	err = json.Unmarshal(body, &cr)
	if err != nil {
		fmt.Println("call contract error 4. 💥")
		return CallResult{}, err
	}
	if len(cr.Result) < 64 {
		fmt.Println("call contract error 5. 💥")
		fmt.Printf("unexpected result -> %+v\n", cr)
		return CallResult{}, fmt.Errorf("len(cr.Result) < 64")
	}

	return cr, nil
}

func (s *Status) KeepUpdate() error {
	// for getting status
	statusPayload := strings.Replace(GET_STATUS_PAYLOAD_TEMPLATE, "$", STONE_ID, 1)
	statusPayload = strings.Replace(statusPayload, "ß", CONTRACT_ADDRESS, 1)

	// for getting nonce
	noncePayload := strings.Replace(GET_NONCE_PAYLOAD_TEMPLATE, "@", SENDER_ADDRESS, 1)
	noncePayload = strings.Replace(noncePayload, "ß", CONTRACT_ADDRESS, 1)

	for {
		// get status -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

		crStatus, err := callContract(statusPayload)
		if err != nil {
			fmt.Println(err)
			continue
		}
		tmp := crStatus.Result[128+2:]
		entropyBytes, err := hex.DecodeString(tmp[:64])
		if err != nil {
			fmt.Println("decode entropyBytes error ❌", err)
			continue
		}
		difficultyBytes, err := hex.DecodeString(tmp[64:128])
		if err != nil {
			fmt.Println("decode difficultyBytes error ‼️", err)
			continue
		}

		// get nonce -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

		crNonce, err := callContract(noncePayload)
		if err != nil {
			fmt.Println(err)
			continue
		}
		nonceBytes, err := hex.DecodeString(crNonce.Result[2:])
		if err != nil {
			fmt.Println("decode nonceBytes error 🚨", err)
			continue
		}
		if len(nonceBytes) != 32 {
			fmt.Println("len of nonceBytes is not 32 🚨", crNonce.Result)
			continue
		}

		// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

		s.SetNED(nonceBytes, entropyBytes, difficultyBytes)
		fmt.Println("\nupdate new nonce = ", big.NewInt(0).SetBytes(s.Nonce))
		fmt.Println("update new difficulty = ", s.Difficulty)
		fmt.Println("update new entropy = ", hex.EncodeToString(s.Entropy))

		// sleep 10 secs before start the next fetching
		time.Sleep(10 * time.Second)

		continue
	}
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func getVal(status *Status) {
	data := status.GetData()
	salt, _ := randomHex(30)
	saltBytes, _ := hex.DecodeString(fmt.Sprintf("%064s", salt))

	saltInt := big.NewInt(0)
	saltInt.SetBytes(saltBytes)

	hash := sha3.NewKeccak256()
	hash.Write(append(data, saltBytes...))
	luck := hash.Sum(nil)

	val := big.NewInt(0)
	val.SetBytes(luck)

	dv := new(big.Int).Div(status.MaxInt, status.Difficulty)

	if val.Cmp(dv) < 1 {
		fmt.Println("\n🌝 Success 👉👉 ", val.Cmp(dv) < 1)
		fmt.Println("⭐️ ValLuck 👉👉 ", val)
		fmt.Println("🌞 SaltInt 👉👉 ", saltInt)
		fmt.Println()
	}
}

func main() {

	status := NewStatus()
	go status.KeepUpdate()

	for status.Difficulty.Cmp(big.NewInt(0)) <= 0 {
	}

	// status.GetVal()

	// if 0 == 0 {
	// 	return
	// }

	n := 32

	current := time.Now().UnixNano()
	var wg sync.WaitGroup
	i := 0
	for -1 < i {
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				getVal(status)
				wg.Done()
			}()
		}
		wg.Wait()
		i += n

		// 2 ** 17 - 1 -> 131071
		// 2 ** 18 - 1 -> 262143
		// 2 ** 19 - 1 -> 524287
		// 2 ** 20 - 1 -> 1048575
		if i&131071 == 0 {
			fmt.Printf("\riteration %d , time : %d", i, time.Now().UnixNano()-current)
			current = time.Now().UnixNano()
		}
	}

	fmt.Println("Finished")
}
