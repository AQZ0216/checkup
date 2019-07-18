package checkup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/sourcegraph/checkup/utils"
)

// TronLedgerChecker implements a Checker for Tron ledger endpoints.
type TronLedgerChecker struct {
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
func (c TronLedgerChecker) Check() (Result, error) {
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
	url := fmt.Sprintf("%s%s?ac=%s&t=%d", c.URL, "/v1/tron/block/latestblockinfo", c.MyAPICode, t)
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
func (c TronLedgerChecker) doChecks(req *http.Request) Attempts {
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
func (c TronLedgerChecker) conclude(result Result) Result {
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
func (c TronLedgerChecker) checkDown(resp *http.Response) error {

	// Check status code
	if resp.StatusCode != c.UpStatus {
		return fmt.Errorf("response status %s", resp.Status)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %v", err)
	}

	// {"error_code":0,"result":585628}

	// parse blockheight
	var checkresult = new(blockNumberResultInt64)
	err = json.Unmarshal(bodyBytes, &checkresult)
	if err != nil {
		return err
	}

	lastTronCheckBlockNum := checkresult.BlockNumber

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

	lastTronBlockNum := tronresult.GetBlockHeight()

	log.Printf("%s, %s BlockHeight:%d, check url:%s last block BlockHeight:%d\n", c.Name, url, lastTronBlockNum, c.URL, lastTronCheckBlockNum)

	blockDiff := lastTronBlockNum - lastTronCheckBlockNum
	if (lastTronBlockNum > lastTronCheckBlockNum) && (blockDiff > int64(c.BlockHeightBehind)) {
		return fmt.Errorf("%s blockheight(%d) was behind trongrid %s (%d) > %d blocks, threshold(%d)", c.Name, lastTronCheckBlockNum, url, lastTronBlockNum, blockDiff, c.BlockHeightBehind)
	}

	return nil
}
