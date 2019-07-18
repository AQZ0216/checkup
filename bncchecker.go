package checkup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sourcegraph/checkup/utils"
)

/*
```
Summary: Get node information.
https://docs.binance.org/api-reference/node-rpc.html#node-rpc
URL for mainnet: http://dataseed1.binance.org:80/status
URL for testnet: http://data-seed-pre-0-s1.binance.org:80/status
latest_block_height
{
	"jsonrpc": "2.0",
	"id": "",
	"result": {
	  "node_info": {
		"protocol_version": {
		  "p2p": "7",
		  "block": "10",
		  "app": "0"
		},
		"id": "782303c9060d46211225662fdd1dd411c638263a",
		"listen_addr": "52.197.243.252:27146",
		"network": "Binance-Chain-Tigris",
		"version": "0.30.1",
		"channels": "354020212223303800",
		"moniker": "data-seed-0",
		"other": {
		  "tx_index": "on",
		  "rpc_address": "tcp://0.0.0.0:27147"
		}
	  },
	  "sync_info": {
		"latest_block_hash": "FF42CE48AC5987F7CD4A051B757A1B58B066081A2DDC006AA8F168CD5045C835",
		"latest_app_hash": "D7C80CE18D1D1D5103CFA3221DF5C51EE8D3F5949DA3E943E782B7B227123D96",
		"latest_block_height": "12766888",
		"latest_block_time": "2019-06-13T06:37:04.78651439Z",
		"catching_up": false
	  },
	  "validator_info": {
		"address": "A88BAB486162E44380AA456DFA7C1DCD997985D9",
		"pub_key": {
		  "type": "tendermint/PubKeyEd25519",
		  "value": "TYgEeiyMDbt8drIPkoyAMcISvlTNVQGU6NUsL4uWEG0="
		},
		"voting_power": "0"
	  }
	}
  }
```
*/

type BNBStatus struct {
	StatusRPCVer string             `json:"jsonrpc`
	StatusResult StatusResultStruct `json:"result"`
	// TODO: Transactions
}

/*
{
  "node_info": {
    "protocol_version": {
      "p2p": 7,
      "block": 10,
      "app": 0
    },
    "id": "f52252fcda9c161c0089d971c9f1b941a26023ef",
    "listen_addr": "10.211.33.206:27146",
    "network": "Binance-Chain-Tigris",
    "version": "0.30.1",
    "channels": "3540202122233038",
    "moniker": "Everest",
    "other": {
      "tx_index": "on",
      "rpc_address": "tcp://0.0.0.0:27147"
    }
  },
  "sync_info": {
    "latest_block_hash": "0A82DF62E127C346DF3227A2E11B880A05FC4BEE3D1D97A24577B3506CCF9FD7",
    "latest_app_hash": "C427816633C9B631B8059A3391B94F3ADEDD716DE6E682325B55AB7A929D47A2",
    "latest_block_height": 16723750,
    "latest_block_time": "2019-06-30T03:27:11.31300562Z",
    "catching_up": false
  },*/

type BNBDEXAPIStatus struct {
	SyncInfoData SyncInfoStruct `json:"sync_info"`
	// TODO: Transactions
}

type StatusResultStruct struct {
	SyncInfoData SyncInfoStruct `json:"sync_info"`
}

type SyncInfoStruct struct {
	SyncInfo_latest_block_hash   string `json:"latest_block_hash"`
	SyncInfo_latest_app_hash     string `json:"latest_app_hash"`
	SyncInfo_latest_block_height string `json:"latest_block_height"`
	SyncInfo_latest_block_time   string `json:"latest_block_time"`
	SyncInfo_catching_up         bool   `json:"catching_up"`
}

// GetBlockHeight return the block height
func (bc *BNBStatus) GetLatestBlockHeight() string {
	return bc.StatusResult.SyncInfoData.SyncInfo_latest_block_height
}

// GetTimestamp return the block timestamp
func (bc *BNBStatus) GetLatestBlockTimestamp() string {
	return bc.StatusResult.SyncInfoData.SyncInfo_latest_block_time
}

// GetBlockHashString return the hex encoded string of the block hash
func (bc *BNBStatus) GetLatestBlockHashString() string {
	return bc.StatusResult.SyncInfoData.SyncInfo_latest_block_hash
}

// BNCChecker implements a Checker for Binance chain endpoints.
type BNCChecker struct {
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
func (c BNCChecker) Check() (Result, error) {
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
func (c BNCChecker) doChecks(req *http.Request) Attempts {
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
func (c BNCChecker) conclude(result Result) Result {
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
func (c BNCChecker) checkDown(resp *http.Response) error {

	// Check status code
	if resp.StatusCode != c.UpStatus {
		return fmt.Errorf("response status %s", resp.Status)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %v", err)
	}
	// parse blockheight
	var checkresult = new(BNBStatus)
	err = json.Unmarshal(bodyBytes, &checkresult)
	if err != nil {
		return fmt.Errorf("Unmarshal response body: %v", err)
	}

	var lastBNBBlockNum int64
	if c.ReferURL == "" {
		c.ReferURL = "https://dex.binance.org/api/v1/node-info"
		log.Printf("use default, set c.ReferURL:%s\n", c.ReferURL)
	}

	if c.ReferURL == "http://dataseed1.binance.org:80/status" {
		lastBNBBlockNum, err = c.getHeightDataseed1()
	} else if c.ReferURL == "https://dex.binance.org/api/v1/node-info" {
		lastBNBBlockNum, err = c.getHeightDEXAPI()
	} else {
		return fmt.Errorf("unsupported c.ReferURL:%s", c.ReferURL)
	}

	lastBNBCheckBlockNum, _ := strconv.ParseInt(checkresult.GetLatestBlockHeight(), 10, 64)
	blockDiff := lastBNBBlockNum - lastBNBCheckBlockNum
	log.Printf("BNC(%s) %s BlockHeight:%d, check url:%s last block BlockHeight:%d\n", c.Name, c.ReferURL, lastBNBBlockNum, c.URL, lastBNBCheckBlockNum)
	if (lastBNBBlockNum > lastBNBCheckBlockNum) && (blockDiff > int64(c.BlockHeightBehind)) {
		return fmt.Errorf("blockheight(%d) was behind BNC %s (%d) > %d blocks, threshold(%d)", lastBNBCheckBlockNum, c.ReferURL, lastBNBBlockNum, blockDiff, c.BlockHeightBehind)
	}

	return nil
}

func (c BNCChecker) getHeightDataseed1() (int64, error) {
	var responsebody []byte
	url := "http://dataseed1.binance.org:80/status"
	if c.ReferURL != "" {
		log.Printf("BNC(%s) height ReferURL:%s\n", c.Name, c.ReferURL)
		url = c.ReferURL
	}

	responsebodyStr := utils.GlobalCacheGetString(url)
	if responsebodyStr == "" {
		client := &http.Client{}

		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte("")))
		req.Header.Set("Content-Type", "application/json")

		res, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer res.Body.Close()

		responsebody, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return 0, err
		}
		str := string(responsebody[:])
		utils.GlobalCacheSetString(url, str)
	} else {
		log.Printf("BNC(%s) use cache key: %s", c.Name, url)
		responsebody = []byte(responsebodyStr)
	}

	var bnbresult = new(BNBStatus)
	err := json.Unmarshal(responsebody, &bnbresult)
	if err != nil {
		return 0, fmt.Errorf("url:%s Unmarshal response body: %v", url, err)
	}

	lastBNBBlockNum, err := strconv.ParseInt(bnbresult.GetLatestBlockHeight(), 10, 64)

	return lastBNBBlockNum, err
}

func (c BNCChecker) getHeightDEXAPI() (int64, error) {

	var responsebody []byte
	url := "https://dex.binance.org/api/v1/node-info"
	if c.ReferURL != "" {
		log.Printf("BNC(%s) height ReferURL:%s\n", c.Name, c.ReferURL)
		url = c.ReferURL
	}

	responsebodyStr := utils.GlobalCacheGetString(url)
	if responsebodyStr == "" {
		client := &http.Client{}

		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte("")))
		req.Header.Set("Content-Type", "application/json")

		res, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer res.Body.Close()

		responsebody, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return 0, err
		}
		str := string(responsebody[:])
		utils.GlobalCacheSetString(url, str)
	} else {
		log.Printf("BNC(%s) use cache key: %s", c.Name, url)
		responsebody = []byte(responsebodyStr)
	}

	var bnbresult = new(BNBDEXAPIStatus)
	err := json.Unmarshal(responsebody, &bnbresult)
	if err != nil {
		return 0, fmt.Errorf("url:%s Unmarshal response body: %v", url, err)
	}

	lastBNBBlockNum, err := strconv.ParseInt(bnbresult.SyncInfoData.SyncInfo_latest_block_height, 10, 64)

	return lastBNBBlockNum, err
}
