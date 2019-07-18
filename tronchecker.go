package checkup

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/sourcegraph/checkup/utils"
)

type Block struct {
	BlockID     string      `json:"blockID`
	BlockHeader BlockHeader `json:"block_header"`
	// TODO: Transactions
}

type BlockHeader struct {
	Witness string  `json:"witness_signature"`
	RawData RawData `json:"raw_data"`
}

type RawData struct {
	TxTrieRoot    string `json:"txTrieRoot"`
	ParentHash    string `json:"parentHash"`
	Timestamp     int64  `json:"timestamp"`
	Number        int64  `json:"number"`
	WitnessAdress string `json:"witness_address"`
	Version       int    `json:"version"`
}

// GetBlockID return the block ID
func (bc *Block) GetBlockID() string {
	return bc.BlockID
}

// GetBlockHeight return the block height
func (bc *Block) GetBlockHeight() int64 {
	return bc.BlockHeader.RawData.Number
}

// GetTimestamp return the block timestamp
func (bc *Block) GetTimestamp() int64 {
	return bc.BlockHeader.RawData.Timestamp
}

// GetBlockHash return the block hash, the calculation defined in java-tron/src/main/java/org/tron/core/capsule/TransactionCapsule.java:setReference()
// setRefBlockHash(ByteString.copyFrom(ByteArray.subArray(blockHash, 8, 16)))
func (bc *Block) GetBlockHash() []byte {
	blockHash, _ := hex.DecodeString(bc.GetBlockID())
	return blockHash[8:16]
}

// GetBlockBytes return the block hash, the calculation defined in java-tron/src/main/java/org/tron/core/capsule/TransactionCapsule.java:setReference()
// setRefBlockBytes(ByteString.copyFrom(ByteArray.subArray(refBlockNum, 6, 8)))
func (bc *Block) GetBlockBytes() []byte {
	var buf = make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(bc.GetBlockHeight()))
	return buf[6:8]
}

// GetBlockHashString return the hex encoded string of the block hash
func (bc *Block) GetBlockHashString() string {
	return hex.EncodeToString(bc.GetBlockHash())
}

// GetBlockBytesString return the hex encoded string of the block bytes
func (bc *Block) GetBlockBytesString() string {
	return hex.EncodeToString(bc.GetBlockBytes())
}

// TronChecker implements a Checker for Tron endpoints.
type TronChecker struct {
	// Name is the name of the endpoint.
	Name string `json:"endpoint_name"`

	// URL is the URL of the endpoint.
	URL string `json:"endpoint_url"`

	// User is the user name
	User string `json:"user"`
	// Password is the password
	Password string `json:"password"`
	// BlockHeightBehind is the threshold of the current block height behind etherscan
	BlockHeightBehind uint32 `json:"blockHeightBehind"`

	// URL is the URL of the endpoint.
	ReferURL string `json:"refer_url,omitempty"`

	// UpStatus is the HTTP status code expected by
	// a healthy endpoint. Default is http.StatusOK.
	UpStatus int `json:"up_status,omitempty"`

	// ThresholdRTT is the maximum round trip time to
	// allow for a healthy endpoint. If non-zero and a
	// request takes longer than ThresholdRTT, the
	// endpoint will be considered unhealthy. Note that
	// this duration includes any in-between network
	// latency.
	ThresholdRTT time.Duration `json:"threshold_rtt,omitempty"`

	// MustContain is a string that the response body
	// must contain in order to be considered up.
	// NOTE: If set, the entire response body will
	// be consumed, which has the potential of using
	// lots of memory and slowing down checks if the
	// response body is large.
	MustContain string `json:"must_contain,omitempty"`

	// MustNotContain is a string that the response
	// body must NOT contain in order to be considered
	// up. If both MustContain and MustNotContain are
	// set, they are and-ed together. NOTE: If set,
	// the entire response body will be consumed, which
	// has the potential of using lots of memory and
	// slowing down checks if the response body is large.
	MustNotContain string `json:"must_not_contain,omitempty"`

	// Attempts is how many requests the client will
	// make to the endpoint in a single check.
	Attempts int `json:"attempts,omitempty"`

	// AttemptSpacing spaces out each attempt in a check
	// by this duration to avoid hitting a remote too
	// quickly in succession. By default, no waiting
	// occurs between attempts.
	AttemptSpacing time.Duration `json:"attempt_spacing,omitempty"`

	// Client is the http.Client with which to make
	// requests. If not set, DefaultHTTPClient is
	// used.
	Client *http.Client `json:"-"`

	// Headers contains headers to added to the request
	// that is sent for the check
	Headers http.Header `json:"headers,omitempty"`
}

// Check performs checks using c according to its configuration.
// An error is only returned if there is a configuration error.
func (c TronChecker) Check() (Result, error) {
	if c.Attempts < 1 {
		c.Attempts = 1
	}
	if c.Client == nil {
		c.Client = DefaultHTTPClient
	}
	if c.UpStatus == 0 {
		c.UpStatus = http.StatusOK
	}

	result := Result{Title: c.Name, Endpoint: c.URL, Timestamp: Timestamp()}
	req, err := http.NewRequest("POST", c.URL, bytes.NewBuffer([]byte("")))
	req.Header.Set("Content-Type", "application/json")

	if c.User != "" && c.Password != "" {
		req.SetBasicAuth(c.User, c.Password)
	}

	if err != nil {
		return result, err
	}

	if c.Headers != nil {
		for key, header := range c.Headers {
			req.Header.Add(key, strings.Join(header, ", "))
		}
	}

	result.Times = c.doChecks(req)

	return c.conclude(result), nil
}

// doChecks executes req using c.Client and returns each attempt.
func (c TronChecker) doChecks(req *http.Request) Attempts {
	checks := make(Attempts, c.Attempts)
	for i := 0; i < c.Attempts; i++ {
		start := time.Now()
		resp, err := c.Client.Do(req)
		checks[i].RTT = time.Since(start)
		if err != nil {
			checks[i].Error = err.Error()
			continue
		}
		err = c.checkDown(resp)
		if err != nil {
			checks[i].Error = err.Error()
		}
		resp.Body.Close()
		if c.AttemptSpacing > 0 {
			time.Sleep(c.AttemptSpacing)
		}
	}
	return checks
}

// conclude takes the data in result from the attempts and
// computes remaining values needed to fill out the result.
// It detects degraded (high-latency) responses and makes
// the conclusion about the result's status.
func (c TronChecker) conclude(result Result) Result {
	result.ThresholdRTT = c.ThresholdRTT

	// Check errors (down)
	for i := range result.Times {
		if result.Times[i].Error != "" {
			result.Down = true
			result.Message = result.Times[i].Error
			return result
		}
	}

	// Check round trip time (degraded)
	if c.ThresholdRTT > 0 {
		stats := result.ComputeStats()
		if stats.Median > c.ThresholdRTT {
			result.Notice = fmt.Sprintf("median round trip time exceeded threshold (%s)", c.ThresholdRTT)
			result.Degraded = true
			return result
		}
	}

	result.Healthy = true
	return result
}

// checkDown checks whether the endpoint is down based on resp and
// the configuration of c. It returns a non-nil error if down.
// Note that it does not check for degraded response.
func (c TronChecker) checkDown(resp *http.Response) error {

	// Check status code
	if resp.StatusCode != c.UpStatus {
		return fmt.Errorf("response status %s", resp.Status)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %v", err)
	}
	// parse blockheight
	var checkresult = new(Block)
	err = json.Unmarshal(bodyBytes, &checkresult)
	if err != nil {
		return err
	}

	//now := time.Now().UnixNano()
	//then := checkresult.GetTimestamp()
	//log.Printf("url:%s last block BlockHeight:%d\n", c.URL, checkresult.GetBlockHeight())
	//i, _ := strconv.ParseInt(timestamp.(string), 10, 64)
	//log.Printf("%d", i)
	//["block_header"]["raw_data"]["number"]

	/* https://developers.tron.network/reference#wallet-getnowblock
		curl -X POST  https://api.trongrid.io/wallet/getnowblock
	{
		"block": [
		{
	      "block_header": {
	        "raw_data": {
	          "timestamp": 1552949766000,
	          "txTrieRoot": "d9b24867ce1b1134e033701addfdeca4f5f17d4d0ed8ff9e684a2ff16ba68629",
	          "parentHash": "0000000000741b9d468ba7f17caf68490d91f94794652466e8eb187fc168a9ee",
	          "number": 7609246,
	          "witness_address": "41beab998551416b02f6721129bb01b51fceceba08",
	          "version": 7
	*/

	var responsebody []byte
	url := "https://api.trongrid.io/wallet/getnowblock"
	if c.ReferURL != "" {
		log.Printf("TRON(%s) height ReferURL:%s\n", c.Name, c.ReferURL)
		url = c.ReferURL
	}

	responsebodyStr := utils.GlobalCacheGetString(url)
	if responsebodyStr == "" {
		client := &http.Client{}

		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte("")))
		req.Header.Set("Content-Type", "application/json")

		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()

		responsebody, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		str := string(responsebody[:])
		utils.GlobalCacheSetString(url, str)
	} else {
		log.Printf("TRON(%s) use cache key: %s", c.Name, url)
		responsebody = []byte(responsebodyStr)
	}

	var tronresult = new(Block)
	err = json.Unmarshal(responsebody, &tronresult)
	if err != nil {
		return err
	}

	log.Printf("%s, %s BlockHeight:%d, check url:%s last block BlockHeight:%d\n", c.Name, url, tronresult.GetBlockHeight(), c.URL, checkresult.GetBlockHeight())

	lastTronBlockNum := tronresult.GetBlockHeight()
	lastTronCheckBlockNum := checkresult.GetBlockHeight()
	blockDiff := lastTronBlockNum - lastTronCheckBlockNum
	if (lastTronBlockNum > lastTronCheckBlockNum) && (blockDiff > int64(c.BlockHeightBehind)) {
		return fmt.Errorf("%s blockheight(%d) was behind trongrid %s (%d) > %d blocks, threshold(%d)", c.Name, lastTronCheckBlockNum, url, lastTronBlockNum, blockDiff, c.BlockHeightBehind)
	}

	return nil
}
