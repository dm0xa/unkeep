// Command loadtest drives the full create -> challenge -> open -> receipt ->
// decrypt-confirmation flow. Run it only against a disposable instance: it
// burns every secret it creates and fills the receipt store.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

type createResponse struct {
	SecretID     string `json:"secretId"`
	ReceiptToken string `json:"receiptToken"`
}

type challengeResponse struct {
	Challenge string `json:"challenge"`
}

type openResponse struct {
	ViewToken string `json:"viewToken"`
}

type latencySet struct {
	create    []time.Duration
	challenge []time.Duration
	open      []time.Duration
	receipt   []time.Duration
	decrypted []time.Duration
	cycle     []time.Duration
}

type workerResult struct {
	lat    latencySet
	cycles int64
	errors int64
}

func makeProof() string {
	h := sha256.New()
	h.Write([]byte("not-saved:open-proof:v1"))
	h.Write(make([]byte, 32))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func makeRequestBody(ciphertextBytes int) string {
	zero := make([]byte, ciphertextBytes)
	body, _ := json.Marshal(map[string]any{
		"envelope": map[string]any{
			"v":          1,
			"alg":        "A256GCM",
			"iv":         base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
			"ciphertext": base64.RawURLEncoding.EncodeToString(zero),
			"tag":        base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
			"createdAt":  0,
			"expiresAt":  0,
			"maxViews":   1,
		},
		"ttlSeconds": 60,
		"proof":      makeProof(),
	})
	return string(body)
}

func main() {
	base := flag.String("url", "http://127.0.0.1:8091", "base URL")
	workers := flag.Int("workers", 64, "concurrent workers")
	duration := flag.Duration("duration", 10*time.Second, "run duration")
	ciphertextBytes := flag.Int("bytes", 32, "ciphertext bytes per secret")
	flag.Parse()
	requestBody := makeRequestBody(*ciphertextBytes)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        *workers * 2,
			MaxIdleConnsPerHost: *workers * 2,
			MaxConnsPerHost:     0,
			DisableCompression:  true,
			IdleConnTimeout:     60 * time.Second,
		},
	}

	results := make(chan workerResult, *workers)
	deadline := time.Now().Add(*duration)
	var wg sync.WaitGroup
	for range *workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var res workerResult
			cookie := ""
			for time.Now().Before(deadline) {
				lat, err := oneCycle(client, *base, requestBody, &cookie)
				if err != nil {
					res.errors++
					continue
				}
				res.lat.create = append(res.lat.create, lat[0])
				res.lat.challenge = append(res.lat.challenge, lat[1])
				res.lat.open = append(res.lat.open, lat[2])
				res.lat.receipt = append(res.lat.receipt, lat[3])
				res.lat.decrypted = append(res.lat.decrypted, lat[4])
				res.lat.cycle = append(res.lat.cycle, lat[5])
				res.cycles++
			}
			results <- res
		}()
	}
	start := time.Now()
	wg.Wait()
	close(results)
	elapsed := time.Since(start)

	var all latencySet
	var cycles, errors int64
	for res := range results {
		cycles += res.cycles
		errors += res.errors
		all.create = append(all.create, res.lat.create...)
		all.challenge = append(all.challenge, res.lat.challenge...)
		all.open = append(all.open, res.lat.open...)
		all.receipt = append(all.receipt, res.lat.receipt...)
		all.decrypted = append(all.decrypted, res.lat.decrypted...)
		all.cycle = append(all.cycle, res.lat.cycle...)
	}

	fmt.Printf("workers=%d duration=%s elapsed=%s cycles=%d errors=%d cycles/s=%.1f req/s=%.1f\n",
		*workers, duration.String(), elapsed.Round(time.Millisecond), cycles, errors,
		float64(cycles)/elapsed.Seconds(), float64(cycles*5)/elapsed.Seconds())
	printSet("create", all.create)
	printSet("challenge", all.challenge)
	printSet("open", all.open)
	printSet("receipt", all.receipt)
	printSet("decrypted", all.decrypted)
	printSet("full cycle", all.cycle)
}

func oneCycle(client *http.Client, base, requestBody string, cookie *string) ([6]time.Duration, error) {
	var out [6]time.Duration
	start := time.Now()

	t := time.Now()
	req, _ := http.NewRequest(http.MethodPost, base+"/api/secrets", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return out, err
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	out[0] = time.Since(t)
	if res.StatusCode != http.StatusCreated {
		return out, fmt.Errorf("create %d %s", res.StatusCode, body)
	}
	var created createResponse
	if err := json.Unmarshal(body, &created); err != nil {
		return out, err
	}

	t = time.Now()
	res, err = client.Get(base + "/api/secrets/" + created.SecretID)
	if err != nil {
		return out, err
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	out[1] = time.Since(t)
	if res.StatusCode != http.StatusOK {
		return out, fmt.Errorf("challenge %d %s", res.StatusCode, body)
	}
	if cookies := res.Cookies(); len(cookies) > 0 {
		*cookie = cookies[0].String()
	}
	var challenge challengeResponse
	if err := json.Unmarshal(body, &challenge); err != nil {
		return out, err
	}

	t = time.Now()
	openBody, _ := json.Marshal(map[string]string{"challenge": challenge.Challenge, "confirmation": "reveal"})
	req, _ = http.NewRequest(http.MethodPost, base+"/api/secrets/"+created.SecretID+"/open", bytes.NewReader(openBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Not-Saved-Confirm", "reveal")
	req.Header.Set("X-Secret-Proof", makeProof())
	req.Header.Set("Cookie", *cookie)
	res, err = client.Do(req)
	if err != nil {
		return out, err
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	out[2] = time.Since(t)
	if res.StatusCode != http.StatusOK {
		return out, fmt.Errorf("open %d %s", res.StatusCode, body)
	}
	var opened openResponse
	if err := json.Unmarshal(body, &opened); err != nil {
		return out, err
	}

	t = time.Now()
	req, _ = http.NewRequest(http.MethodPost, base+"/api/secrets/"+created.SecretID+"/receipt", nil)
	req.Header.Set("X-Receipt-Token", created.ReceiptToken)
	res, err = client.Do(req)
	if err != nil {
		return out, err
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	out[3] = time.Since(t)
	if res.StatusCode != http.StatusOK {
		return out, fmt.Errorf("receipt %d %s", res.StatusCode, body)
	}

	t = time.Now()
	decBody, _ := json.Marshal(map[string]string{"viewToken": opened.ViewToken})
	req, _ = http.NewRequest(http.MethodPost, base+"/api/secrets/"+created.SecretID+"/decrypted", bytes.NewReader(decBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Not-Saved-Confirm", "reveal")
	res, err = client.Do(req)
	if err != nil {
		return out, err
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	out[4] = time.Since(t)
	if res.StatusCode != http.StatusOK {
		return out, fmt.Errorf("decrypted %d %s", res.StatusCode, body)
	}
	out[5] = time.Since(start)
	return out, nil
}

func printSet(name string, values []time.Duration) {
	if len(values) == 0 {
		fmt.Printf("%-11s n=0\n", name)
		return
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	p := func(q float64) time.Duration {
		idx := int(float64(len(values)-1) * q)
		return values[idx]
	}
	fmt.Printf("%-11s n=%-7d p50=%-9s p95=%-9s p99=%-9s max=%s\n",
		name, len(values), p(0.50).Round(time.Microsecond), p(0.95).Round(time.Microsecond),
		p(0.99).Round(time.Microsecond), values[len(values)-1].Round(time.Microsecond))
}
