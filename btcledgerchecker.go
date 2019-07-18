package checkup

import (
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

// BTCLedgerChecker implements a Checker for BTC ledger fullnode.
type BTCLedgerChecker struct {
	// Name is the name of the endpoint.
	Name string `json:"endpoint_name"`

	// URL is the URL of the endpoint.
	URL string `json:"endpoint_url"`

	// Param is the parameters in json string format
	Param string `json:"parameters"`

	// User is the user name
	User string `json:"user"`
	// Password is the password
	Password string `json:"password"`
	// BlockHeightBehind is the threshold of the current block height behind etherscan
	BlockHeightBehind int64  `json:"blockHeightBehind"`
	Coin              string `json:"coin"`
	MyAPICode         string `json:"myAPICode"`
	MySecretKey       string `json:"mySecretKey"`
	SigHeader         string `json:"sigHeader"`

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
func (c BTCLedgerChecker) Check() (Result, error) {
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

	t := time.Now().Unix()
	url := fmt.Sprintf("%s%s?ac=%s&t=%d", c.URL, "/v1/"+c.Coin+"/block/latestblockinfo", c.MyAPICode, t)
	req, err := http.NewRequest("GET", url, nil)

	req.Header.Set(c.SigHeader, utils.BuildSign(nil, c.MySecretKey, t))

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
func (c BTCLedgerChecker) doChecks(req *http.Request) Attempts {
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
func (c BTCLedgerChecker) conclude(result Result) Result {
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
func (c BTCLedgerChecker) checkDown(resp *http.Response) error {
	type blockchainInfo struct {
		Blocks int64 `json:"blocks"`
	}
	type result struct {
		Error  string         `json:"error"`
		ID     string         `json:"id"`
		Result blockchainInfo `json:"result"`
	}

	// Check status code
	if resp.StatusCode != c.UpStatus {
		return fmt.Errorf("response status %s", resp.Status)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %v", err)
	}

	// {"error_code":0,"result":585628}

	// parse block height
	var r = new(blockNumberResultInt64)
	err = json.Unmarshal(bodyBytes, r)
	if err != nil {
		return fmt.Errorf("Unmarshal response body: %v", err)
	}
	currentBlockNum := r.BlockNumber

	var refBlockNum int64
	if c.ReferURL == "https://chain.so/api/v2/get_info/LTC" {
		refBlockNum, err = c.getHeightLTC()
	} else if c.ReferURL == "https://blockchain.info/q/getblockcount" {
		refBlockNum, err = c.getHeightBTC()
	} else if c.ReferURL == "https://blockdozer.com/insight-api/status?q=getInfo" {
		refBlockNum, err = c.getHeightBCHABC()
	} else if c.ReferURL == "http://www.tokenview.com:8088/coin/latest/BCH" {
		refBlockNum, err = c.getHeightBCHABCtokenview()
	} else {
		return fmt.Errorf("unsupported c.ReferURL:%s", c.ReferURL)
	}

	if err != nil {
		return err
	}

	log.Printf("%s, ref:%s BlockHeight:%d      check:%s last block BlockHeight:%d\n", c.Name, c.ReferURL, currentBlockNum, c.URL, refBlockNum)

	blockDiff := refBlockNum - currentBlockNum
	if blockDiff > c.BlockHeightBehind {
		return fmt.Errorf("blockheight(%d) was behind blockchain.info (%d) %d blocks, threshold(%d)", currentBlockNum, refBlockNum, blockDiff, c.BlockHeightBehind)
	}

	// Check response body
	if c.MustContain == "" && c.MustNotContain == "" {
		return nil
	}

	body := string(bodyBytes)
	if c.MustContain != "" && !strings.Contains(body, c.MustContain) {
		return fmt.Errorf("response does not contain '%s'", c.MustContain)
	}
	if c.MustNotContain != "" && strings.Contains(body, c.MustNotContain) {
		return fmt.Errorf("response contains '%s'", c.MustNotContain)
	}

	return nil
}

func (c BTCLedgerChecker) getHeightBTC() (int64, error) {
	url := "https://blockchain.info/q/getblockcount"
	// 585630

	if c.ReferURL != "" {
		log.Printf("BTC(%s) height ReferURL:%s\n", c.Name, c.ReferURL)
		url = c.ReferURL
	}
	var refBlockNumBytes []byte
	responsebodyStr := utils.GlobalCacheGetString(url)
	if responsebodyStr == "" {
		refResp, err := DefaultHTTPClient.Get(url)
		if err != nil {
			return 0, err
		}
		refBlockNumBytes, err = ioutil.ReadAll(refResp.Body)
		if err != nil {
			return 0, err
		}

		var str = string(refBlockNumBytes[:])
		utils.GlobalCacheSetString(url, str)
	} else {
		log.Printf("BTC(%s) use cache key: %s", c.Name, url)
		refBlockNumBytes = []byte(responsebodyStr)
	}

	// get reference block height from https://blockchain.info/q/getblockcount

	refBlockNum, err := strconv.ParseInt(string(refBlockNumBytes), 10, 64) //convert string to int64
	if err != nil {
		var str = string(refBlockNumBytes[:])
		log.Printf("BTC(%s) incorrect cache: %s", c.Name, str)
		return 0, fmt.Errorf("BTC refer data blockchain.info, Unmarshal response body: %s", str)
	}

	return refBlockNum, err
}

func (c BTCLedgerChecker) getHeightLTC() (int64, error) {
	url := "https://chain.so/api/v2/get_info/LTC"
	/*{
		"status" : "success",
		"data" : {
		  "name" : "Bitcoin",
		  "acronym" : "BTC",
		  "network" : "BTC",
		  "symbol_htmlcode" : "&#3647;",
		  "url" : "http://www.bitcoin.com/",
		  "mining_difficulty" : "7409399249090.253",
		  "unconfirmed_txs" : 8617,
		  "blocks" : 581558,
		  "price" : "9295.91000000",
		  "price_base" : "USD",
		  "price_update_time" : 1561011274,
		  "hashrate" : "72879894000225110000.0"
		}
	}*/

	type referdata struct {
		Blocks int64 `json:"blocks"`
	}
	type referresult struct {
		status string    `json:"status"`
		Data   referdata `json:"data"`
	}

	if c.ReferURL != "" {
		log.Printf("LTC(%s) height ReferURL:%s\n", c.Name, c.ReferURL)
		url = c.ReferURL
	}

	var refBlockNumBytes []byte
	responsebodyStr := utils.GlobalCacheGetString(url)
	if responsebodyStr == "" {
		refResp, err := DefaultHTTPClient.Get(url)
		if err != nil {
			return 0, err
		}
		refBlockNumBytes, err = ioutil.ReadAll(refResp.Body)
		if err != nil {
			return 0, err
		}

		var str = string(refBlockNumBytes[:])
		utils.GlobalCacheSetString(url, str)
	} else {
		log.Printf("LTC(%s) use cache key: %s", c.Name, url)
		refBlockNumBytes = []byte(responsebodyStr)
	}

	var refresult = new(referresult)
	err := json.Unmarshal(refBlockNumBytes, &refresult)
	if err != nil {
		var str = string(refBlockNumBytes[:])
		log.Printf("LTC(%s) incorrect cache: %s", c.Name, str)
		return 0, fmt.Errorf("LTC refer data chain.so, Unmarshal response body: %s", str)
	}
	refBlockNum := refresult.Data.Blocks

	return refBlockNum, err
}

func (c BTCLedgerChecker) getHeightBCHABC() (int64, error) {
	url := "https://blockdozer.com/insight-api/status?q=getInfo"
	/*
		{
		"info": {
			"version": 190300,
			"protocolversion": 70015,
			"blocks": 587817,
			"timeoffset": 0,
			"connections": 8,
			"proxy": "",
			"difficulty": 309789828486.4881,
			"testnet": false,
			"relayfee": 1e-05,
			"errors": "Warning: Unknown block versions being mined! It's possible unknown rules are in effect",
			"network": "livenet"
			}
		}
	*/

	type referinfo struct {
		Blocks int64 `json:"blocks"`
	}
	type referresult struct {
		Info referinfo `json:"info"`
	}

	if c.ReferURL != "" {
		log.Printf("BCH(%s) height ReferURL:%s\n", c.Name, c.ReferURL)
		url = c.ReferURL
	}

	var refBlockNumBytes []byte
	responsebodyStr := utils.GlobalCacheGetString(url)
	if responsebodyStr == "" {
		refResp, err := DefaultHTTPClient.Get(url)
		if err != nil {
			return 0, err
		}
		refBlockNumBytes, err = ioutil.ReadAll(refResp.Body)
		if err != nil {
			return 0, err
		}

		var str = string(refBlockNumBytes[:])
		utils.GlobalCacheSetString(url, str)
	} else {
		log.Printf("BCH(%s) use cache key: %s", c.Name, url)
		refBlockNumBytes = []byte(responsebodyStr)
	}

	var refresult = new(referresult)
	err := json.Unmarshal(refBlockNumBytes, &refresult)
	if err != nil {
		var str = string(refBlockNumBytes[:])
		log.Printf("BCH(%s) incorrect cache: %s", c.Name, str)
		return 0, fmt.Errorf("BCH refer data blockdozer.com, Unmarshal response body: %s", str)
	}
	refBlockNum := refresult.Info.Blocks

	return refBlockNum, err
}

func (c BTCLedgerChecker) getHeightBCHABCtokenview() (int64, error) {
	url := "http://www.tokenview.com:8088/coin/latest/BCH"
	/*
		{"code":1,"msg":"成功","data":589214}
	*/

	type referresult struct {
		CodeData   int64  `json:"code"`
		MsgData    string `json:"msg"`
		HeightData int64  `json:"data"`
	}

	if c.ReferURL != "" {
		log.Printf("BCH(%s) height ReferURL:%s\n", c.Name, c.ReferURL)
		url = c.ReferURL
	}

	var refBlockNumBytes []byte
	responsebodyStr := utils.GlobalCacheGetString(url)
	if responsebodyStr == "" {
		refResp, err := DefaultHTTPClient.Get(url)
		if err != nil {
			return 0, err
		}
		refBlockNumBytes, err = ioutil.ReadAll(refResp.Body)
		if err != nil {
			return 0, err
		}

		var str = string(refBlockNumBytes[:])
		utils.GlobalCacheSetString(url, str)
	} else {
		log.Printf("BCH(%s) use cache key: %s", c.Name, url)
		refBlockNumBytes = []byte(responsebodyStr)
	}

	var refresult = new(referresult)
	err := json.Unmarshal(refBlockNumBytes, &refresult)
	if err != nil {
		var str = string(refBlockNumBytes[:])
		log.Printf("BCH(%s) incorrect cache: %s", c.Name, str)
		return 0, fmt.Errorf("BCH refer data tokenview.com, Unmarshal response body: %s", str)
	}
	refBlockNum := refresult.HeightData

	return refBlockNum, err
}
