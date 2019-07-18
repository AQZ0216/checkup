package checkup

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/sourcegraph/checkup/utils"
)

// XRPLedgerChecker implements a Checker for XRP ledger fullnode.
type XRPLedgerChecker struct {
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
func (c XRPLedgerChecker) Check() (Result, error) {
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
	url := fmt.Sprintf("%s%s?ac=%s&t=%d", c.URL, "/v1/xrp/block/latestblockinfo", c.MyAPICode, t)
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
func (c XRPLedgerChecker) doChecks(req *http.Request) Attempts {
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
func (c XRPLedgerChecker) conclude(result Result) Result {
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
func (c XRPLedgerChecker) checkDown(resp *http.Response) error {
	type ledgerInfo struct {
		Index int64 `json:"ledger_index"`
	}
	type result struct {
		Ledger ledgerInfo `json:"ledger"`
		Result string     `json:"result"`
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

	var responsebody []byte
	url := "https://data.ripple.com/v2/ledgers"
	if c.ReferURL != "" {
		log.Printf("XRP(%s) height ReferURL:%s\n", c.Name, c.ReferURL)
		url = c.ReferURL
	}

	responsebodyStr := utils.GlobalCacheGetString(url)
	if responsebodyStr == "" {
		client := &http.Client{}

		req, err := http.NewRequest("GET", url, nil)
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

	/*{
	"result":"success",
	"ledger":{
		"account_hash":"8D944025CBA365E769DE4081D4B8ADCC37EED45F599B41ED55C93B50844FC031",
		"close_flags":"0","close_time":1563267180,
		"close_time_resolution":"10",
		"ledger_hash":"7F7B4EC805B5D9777F52B920BF2CF3D1D44801864AF52BFC352C520D6F3C01FE",
		"ledger_index":48688664,
		"parent_close_time":1563267171,
		"parent_hash":"F00CA6FBB983E7E2D33D4CE9F102A5DDA1E36A5FF5E55B11AA4367A128451084",
		"total_coins":"99991392454278753",
		"transaction_hash":"EFF53B0FA801D832C74F8B9E5CEEE4617B179EEA1C6E3917C6B6536F589F887B",
		"tx_count":"51",
		"close_time_human":"2019-Jul-16 08:53:00"}
	}
	*/

	var refResult = new(result)
	err = json.Unmarshal(responsebody, &refResult)
	if err != nil {
		return err
	}

	refBlockNum := refResult.Ledger.Index

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
