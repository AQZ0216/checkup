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

// EOSLedgerChecker implements a Checker for EOS ledger endpoints.
type EOSLedgerChecker struct {
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
func (c EOSLedgerChecker) Check() (Result, error) {
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
	url := fmt.Sprintf("%s%s?ac=%s&t=%d", c.URL, "/v1/eos/block/latestblockinfo", c.MyAPICode, t)
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
func (c EOSLedgerChecker) doChecks(req *http.Request) Attempts {
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
func (c EOSLedgerChecker) conclude(result Result) Result {
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
func (c EOSLedgerChecker) checkDown(resp *http.Response) error {
	type blockNumberResult struct {
		LastIrreversibleBlockNum uint32 `json:"last_irreversible_block_num"`
		HeadBlockNum             uint32 `json:"head_block_num"`
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

	// parse blockheight
	var result = new(blockNumberResultInt64)
	err = json.Unmarshal(bodyBytes, result)
	if err != nil {
		return err
	}

	currentBlockNumber := result.BlockNumber

	url := "https://proxy.eosnode.tools/v1/chain/get_info"
	if c.ReferURL != "" {
		log.Printf("EOS(%s) height ReferURL:%s\n", c.Name, c.ReferURL)
		url = c.ReferURL
	}

	/*{
		"server_version":"448287d5",
		"chain_id":"aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906",
		"head_block_num":68939427,
		"last_irreversible_block_num":68939100,
		"last_irreversible_block_id":"041bed5c4a116326d09b38d1974f52ae371a9032972ddd0c5e573bcc04ec30dd",
		"head_block_id":"041beea339a2d233fac959e907ddc21927777807718f9add5ff00426e24d4571",
		"head_block_time":"2019-07-16T07:22:55.000",
		"head_block_producer":"big.one",
		"virtual_block_cpu_limit":148709613,
		"virtual_block_net_limit":1048576000,
		"block_cpu_limit":176832,"block_net_limit":1045056,
		"server_version_string":"v1.7.3"
	}*/

	var responsebody []byte
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
		log.Printf("EOS(%s) use cache key: %s", c.Name, url)
		responsebody = []byte(responsebodyStr)
	}

	var blockInfo = new(blockNumberResult)
	err = json.Unmarshal(responsebody, blockInfo)
	if err != nil {
		return err
	}

	log.Printf("%s, ref:%s BlockHeight:%d      check:%s last block BlockHeight:%d\n", c.Name, url, blockInfo.LastIrreversibleBlockNum, c.URL, currentBlockNumber)

	blockDiff := blockInfo.LastIrreversibleBlockNum - uint32(currentBlockNumber)
	if (blockInfo.LastIrreversibleBlockNum > uint32(currentBlockNumber)) && (blockDiff > c.BlockHeightBehind) {
		return fmt.Errorf("%s blockheight(%d) was behind eos node tool(%d) %d blocks, threshold(%d)", c.Name, currentBlockNumber, blockInfo.LastIrreversibleBlockNum, blockDiff, c.BlockHeightBehind)
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
