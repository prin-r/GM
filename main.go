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
	AggData         []byte
}

const URL = "https://rpcapi.fantom.network"
const CONTRACT_ADDRESS = "342ebf0a5cec4404ccff73a40f9c30288fc72611"
const SENDER_ADDRESS = "932370760e7dd5F32B5F5B09741e97A23965C14c"
const STONE_ID = "0000000000000000000000000000000000000000000000000000000000000000"
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
		AggData:         []byte{},
	}

	return status
}

func (status *Status) GetNED() ([]byte, []byte, *big.Int) {
	status.mutex.RLock()
	defer func() {
		status.mutex.RUnlock()
	}()

	return status.Nonce[:], status.Entropy[:], big.NewInt(0).SetBytes(status.Difficulty.Bytes())
}

func (status *Status) GetADM() ([]byte, *big.Int, *big.Int) {
	status.mutex.RLock()
	defer func() {
		status.mutex.RUnlock()
	}()

	return status.AggData[:], big.NewInt(0).SetBytes(status.Difficulty.Bytes()), big.NewInt(0).SetBytes(status.MaxInt.Bytes())
}

func (status *Status) SetNED(nonceBytes []byte, entropyBytes []byte, difficultyBytes []byte) {
	status.mutex.Lock()
	defer func() {
		status.mutex.Unlock()
	}()

	status.Nonce = nonceBytes[:]
	status.Entropy = entropyBytes[:]
	status.Difficulty = big.NewInt(0).SetBytes(difficultyBytes[:])

	data := []byte{}
	data = append(data, status.ChainID...)
	data = append(data, status.Entropy...)
	data = append(data, status.ContractAddress...)
	data = append(data, status.SenderAddress...)
	data = append(data, status.StoneID...)
	data = append(data, status.Nonce...)

	status.AggData = data

	fmt.Println("chain id -> ", big.NewInt(0).SetBytes(status.ChainID))
	fmt.Println("entropy -> ", hex.EncodeToString(status.Entropy))
	fmt.Println("contract -> ", hex.EncodeToString(status.ContractAddress))
	fmt.Println("sender -> ", hex.EncodeToString(status.SenderAddress))
	fmt.Println("stone -> ", big.NewInt(0).SetBytes(status.StoneID))
	fmt.Println("nonce -> ", big.NewInt(0).SetBytes(status.Nonce))
	fmt.Println("difficulty -> ", status.Difficulty)
	fmt.Println("aggdata -> ", hex.EncodeToString(status.AggData))
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

func (status *Status) KeepUpdate() error {
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

		status.SetNED(nonceBytes, entropyBytes, difficultyBytes)
		// n, e, d := status.GetNED()
		// fmt.Println("\nupdate new nonce = ", big.NewInt(0).SetBytes(n))
		// fmt.Println("update new entropy = ", hex.EncodeToString(e))
		// fmt.Println("update new difficulty = ", d)

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

func claimGem(salt string) {
	// client := &http.Client{}
	// mockPayload := `{
	//     "kind": "$",
	//     "salt": "ß"
	// }`

	// sendPayload := strings.Replace(mockPayload, "$", STONE_ID, 1)
	// sendPayload = strings.Replace(sendPayload, "ß", salt, 1)
	// fmt.Println(sendPayload)

	// req, err := http.NewRequest("POST", "http://167.172.73.117:3000/add", strings.NewReader(sendPayload))
	// if err != nil {
	// 	fmt.Println("claiming gem error 1. 💥")
	// }
	// req.Header.Add("Content-Type", "application/json")

	// _, err = client.Do(req)
	// if err != nil {
	// 	fmt.Println("claiming gem error 2. 💥")
	// }
}

func calValLuck(aggData []byte, saltBytes []byte) *big.Int {
	// fmt.Println("aggData ---> ", hex.EncodeToString(aggData))
	// fmt.Println("saltBytes --->", hex.EncodeToString(saltBytes))
	hash := sha3.NewKeccak256()
	hash.Write(append(aggData, saltBytes...))
	luck := hash.Sum(nil)

	val := big.NewInt(0)
	val.SetBytes(luck)

	return val
}

func getVal(status *Status) {
	aggData, diff, max := status.GetADM()
	salt, _ := randomHex(30)
	saltPadded := fmt.Sprintf("%064s", salt)
	saltBytes, _ := hex.DecodeString(saltPadded)

	val := calValLuck(aggData, saltBytes)

	dv := new(big.Int).Div(max, diff)

	if val.Cmp(dv) < 1 {
		fmt.Println("diff -> ", diff)
		fmt.Println("\n🌝 Success 👉👉 ", val.Cmp(dv) < 1)
		fmt.Println("⭐️ ValLuck 👉👉 ", val)
		fmt.Println("🌞 SaltInt 👉👉 ", big.NewInt(0).SetBytes(saltBytes))
		fmt.Println("saltPadded -> ", saltPadded)
		fmt.Println("claiming gem")
	}
}

func main() {

	// ad, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000fa000080440000047163a56455ac4bc6b1f1b88efadf17db76e5c52c0ca594fd9b342ebf0a5cec4404ccff73a40f9c30288fc72611932370760e7dd5f32b5f5b09741e97a23965c14c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000017")
	// sp, _ := hex.DecodeString("00004ff48ca9ef06ebebdae3caf2b436e1e778c74f4a902601e9d847301e1435")
	// vl := calValLuck(ad, sp)

	// fmt.Println(vl)

	// if 0 == 0 {
	// 	return
	// }

	statusInst := NewStatus()
	go statusInst.KeepUpdate()

	for statusInst.Difficulty.Cmp(big.NewInt(0)) <= 0 {
		_, _, d := statusInst.GetNED()
		if d.Cmp(big.NewInt(0)) > 0 {
			break
		}
	}

	n := 64

	current := time.Now().UnixNano()
	var wg sync.WaitGroup
	i := 0
	for -1 < i {
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				getVal(statusInst)
				wg.Done()
			}()
		}
		wg.Wait()
		i += n

		// 2 ** 17 - 1 -> 131071
		// 2 ** 18 - 1 -> 262143
		// 2 ** 19 - 1 -> 524287
		// 2 ** 20 - 1 -> 1048575
		if i&1048575 == 0 {
			fmt.Printf("\riteration %d , time : %d", i, time.Now().UnixNano()-current)
			current = time.Now().UnixNano()
		}
	}

	fmt.Println("Finished")
}
