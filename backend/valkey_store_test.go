package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func newValkeyTestStore(t *testing.T) (*ValkeyStore, string) {
	t.Helper()
	return newValkeyTestStoreWith(t, StoreConfig{ReceiptGrace: time.Hour})
}

func newValkeyTestStoreWith(t *testing.T, cfg StoreConfig) (*ValkeyStore, string) {
	t.Helper()
	url := os.Getenv("VALKEY_URL")
	if url == "" {
		t.Skip("VALKEY_URL not set")
	}
	prefix := fmt.Sprintf("test:%d:", time.Now().UnixNano())
	store, err := NewValkeyStore(url, prefix, cfg)
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(func() {
		deleteValkeyPrefix(t, store, prefix)
		store.Close()
	})
	return store, prefix
}

func valkeySecretExists(t *testing.T, store *ValkeyStore, id string) bool {
	t.Helper()
	secretKey, _, _ := store.keys(id)
	n, err := store.client.Exists(context.Background(), secretKey).Result()
	if err != nil {
		t.Fatalf("EXISTS %s: %v", secretKey, err)
	}
	return n == 1
}

func deleteValkeyPrefix(t *testing.T, store *ValkeyStore, prefix string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var cursor uint64
	for {
		keys, next, err := store.client.Scan(ctx, cursor, prefix+"*", 1000).Result()
		if err != nil {
			t.Logf("cleanup scan: %v", err)
			return
		}
		if len(keys) > 0 {
			_ = store.client.Del(ctx, keys...).Err()
		}
		cursor = next
		if cursor == 0 {
			return
		}
	}
}

func TestValkeyStoreLifecycle(t *testing.T) {
	store, _ := newValkeyTestStore(t)
	created, err := store.Create(testEnvelope(), time.Minute, testProof())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !validateSecretID(created.SecretID) || !validateToken(created.ReceiptToken, 32) {
		t.Fatal("invalid ids")
	}

	if _, err := store.Consume(created.SecretID, [32]byte{}); !errors.Is(err, ErrProofMismatch) {
		t.Fatalf("wrong proof error = %v", err)
	}
	if view, err := store.Receipt(created.SecretID, created.ReceiptToken); err != nil || view.State != stateAvailable {
		t.Fatalf("wrong proof changed receipt: %+v %v", view, err)
	}

	info, err := store.Challenge(created.SecretID)
	if err != nil || info.SecretID != created.SecretID {
		t.Fatalf("challenge: %+v %v", info, err)
	}
	if _, err := store.Challenge(created.SecretID); err != nil {
		t.Fatal(err)
	}

	consumed, err := store.Consume(created.SecretID, testProof())
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if consumed.Envelope.Ciphertext != base64.RawURLEncoding.EncodeToString(testEnvelope().Ciphertext) {
		t.Fatal("wrong ciphertext")
	}
	if !validateToken(consumed.ViewToken, 32) {
		t.Fatal("invalid view token")
	}
	if valkeySecretExists(t, store, created.SecretID) {
		t.Fatal("burned secret key still exists")
	}
	if _, err := store.Consume(created.SecretID, testProof()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("second consume = %v", err)
	}

	if ok, err := store.ConfirmDecrypted(created.SecretID, "wrong"); err != nil || ok {
		t.Fatal("accepted wrong view token")
	}
	if ok, err := store.ConfirmDecrypted(created.SecretID, consumed.ViewToken); err != nil || !ok {
		t.Fatal("rejected correct view token")
	}
	if ok, err := store.ConfirmDecrypted(created.SecretID, consumed.ViewToken); err != nil || !ok {
		t.Fatal("confirm is not idempotent")
	}

	view, err := store.Receipt(created.SecretID, created.ReceiptToken)
	if err != nil {
		t.Fatal(err)
	}
	if view.State != stateBurned || !view.Decrypted || view.BurnedAt == 0 || view.Opens != 2 {
		t.Fatalf("unexpected receipt: %+v", view)
	}
	want := []string{eventCreated, eventLinkOpened, eventDecryptAttempted, eventBurned, eventDecrypted}
	got := make([]string, len(view.Events))
	for i, event := range view.Events {
		got[i] = event.Type
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v", got)
	}
}

func TestValkeyConcurrentBurnIsAtomic(t *testing.T) {
	store, _ := newValkeyTestStore(t)
	created, err := store.Create(testEnvelope(), time.Minute, testProof())
	if err != nil {
		t.Fatal(err)
	}

	const workers = 32
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Consume(created.SecretID, testProof())
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	unavailable := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrUnavailable):
			unavailable++
		default:
			t.Fatalf("unexpected consume error: %v", err)
		}
	}
	if successes != 1 || unavailable != workers-1 {
		t.Fatalf("successes=%d unavailable=%d", successes, unavailable)
	}
}

func TestValkeyExpiryAndReceipt(t *testing.T) {
	store, _ := newValkeyTestStore(t)
	created, err := store.Create(testEnvelope(), time.Second, testProof())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)

	info, err := store.Challenge(created.SecretID)
	if err != nil || info.SecretID != "" {
		t.Fatalf("expired challenge: %+v %v", info, err)
	}
	if valkeySecretExists(t, store, created.SecretID) {
		t.Fatal("expired secret key still exists")
	}
	view, err := store.Receipt(created.SecretID, created.ReceiptToken)
	if err != nil || view.State != stateExpired {
		t.Fatalf("expired receipt: %+v %v", view, err)
	}
	found := false
	for _, event := range view.Events {
		if event.Type == eventExpired {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing expired event: %+v", view.Events)
	}
}

func TestAPIWithValkeyFullFlow(t *testing.T) {
	url := os.Getenv("VALKEY_URL")
	if url == "" {
		t.Skip("VALKEY_URL not set")
	}
	prefix := fmt.Sprintf("apitest:%d:", time.Now().UnixNano())
	base, client, _, app := newAPIServer(t, func(cfg *Config) {
		cfg.ValkeyURL = url
		cfg.ValkeyPrefix = prefix
		secret := make([]byte, 32)
		for i := range secret {
			secret[i] = byte(i*11 + 5)
		}
		cfg.SessionSecret = secret
	})
	if store, ok := app.store.(*ValkeyStore); ok {
		t.Cleanup(func() { deleteValkeyPrefix(t, store, prefix) })
	} else {
		t.Fatal("server did not use Valkey")
	}

	created, cs, _ := createThroughAPI(t, client, base, "valkey api", 3600)
	challenge := challengeThroughAPI(t, client, base, created.SecretID)
	res, data := openThroughAPI(t, client, base, created.SecretID, challenge.Challenge, cs.proof)
	mustStatus(t, res, data, http.StatusOK)
	var opened apiOpenResponse
	mustJSON(t, data, &opened)
	if got := decryptClientSecret(t, opened.Envelope, cs.key); got != cs.plain {
		t.Fatalf("decrypted %q", got)
	}

	confirmBody, _ := json.Marshal(map[string]string{"viewToken": opened.ViewToken})
	res, data = doJSON(t, client, http.MethodPost, base+"/api/secrets/"+created.SecretID+"/decrypted", confirmBody, map[string]string{
		"X-Not-Saved-Confirm": "reveal",
	})
	mustStatus(t, res, data, http.StatusOK)

	view := receiptThroughAPI(t, client, base, created.SecretID, created.ReceiptToken)
	if view.State != stateBurned || !view.Decrypted || view.Opens != 1 {
		t.Fatalf("receipt = %+v", view)
	}
	res, data = doJSON(t, client, http.MethodGet, base+"/api/secrets/"+created.SecretID, nil, nil)
	mustStatus(t, res, data, http.StatusGone)
}

func TestValkeyRevokeAndStats(t *testing.T) {
	store, _ := newValkeyTestStore(t)
	created, err := store.Create(testEnvelope(), time.Minute, testProof())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Challenge(created.SecretID); err != nil {
		t.Fatal(err)
	}
	if result, err := store.Revoke(created.SecretID, "wrong"); err != nil || result.State != "" {
		t.Fatalf("wrong token revoke = %+v %v", result, err)
	}
	result, err := store.Revoke(created.SecretID, created.ReceiptToken)
	if err != nil || result.State != stateRevoked || result.RevokedAt == 0 {
		t.Fatalf("revoke = %+v %v", result, err)
	}
	if valkeySecretExists(t, store, created.SecretID) {
		t.Fatal("revoked secret key still exists")
	}
	if result, err := store.Revoke(created.SecretID, created.ReceiptToken); err != nil || result.State != stateRevoked {
		t.Fatalf("idempotent revoke = %+v %v", result, err)
	}
	view, err := store.Receipt(created.SecretID, created.ReceiptToken)
	if err != nil || view.State != stateRevoked || view.RevokedAt == 0 {
		t.Fatalf("revoked receipt = %+v %v", view, err)
	}
	if _, err := store.Consume(created.SecretID, testProof()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("consume revoked = %v", err)
	}

	stats := store.Stats()
	if stats.Creates != 1 || stats.Opens != 1 || stats.Revokes != 1 || stats.Burns != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if !store.Ready() {
		t.Fatal("store not ready")
	}
}

func TestValkeyCapacityLimits(t *testing.T) {
	secretStore, _ := newValkeyTestStoreWith(t, StoreConfig{
		ReceiptGrace: time.Hour, MaxSecrets: 1, MaxReceipts: 10, MaxTotalBytes: 64 << 20,
	})
	if _, err := secretStore.Create(testEnvelope(), time.Hour, testProof()); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := secretStore.Create(testEnvelope(), time.Hour, testProof()); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("second create with MAX_SECRETS=1 = %v, want ErrStoreFull", err)
	}

	receiptStore, _ := newValkeyTestStoreWith(t, StoreConfig{
		ReceiptGrace: time.Hour, MaxSecrets: 10, MaxReceipts: 1, MaxTotalBytes: 64 << 20,
	})
	if _, err := receiptStore.Create(testEnvelope(), time.Hour, testProof()); err != nil {
		t.Fatalf("first receipt create: %v", err)
	}
	if _, err := receiptStore.Create(testEnvelope(), time.Hour, testProof()); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("second create with MAX_RECEIPTS=1 = %v, want ErrStoreFull", err)
	}
}

func TestValkeyByteLimitAndReadiness(t *testing.T) {
	store, _ := newValkeyTestStoreWith(t, StoreConfig{
		ReceiptGrace: time.Hour, MaxSecrets: 10, MaxReceipts: 10, MaxTotalBytes: 1 << 20,
	})
	store.usedMemory = func(context.Context) (int64, error) { return 1 << 20, nil }
	if _, err := store.Create(testEnvelope(), time.Hour, testProof()); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("create at byte ceiling = %v, want ErrStoreFull", err)
	}
	store.invalidateReady()
	if store.Ready() {
		t.Fatal("Ready reported capacity at the byte ceiling")
	}
}

func TestValkeyReadinessReflectsCapacity(t *testing.T) {
	store, _ := newValkeyTestStoreWith(t, StoreConfig{
		ReceiptGrace: time.Hour, MaxSecrets: 1, MaxReceipts: 10, MaxTotalBytes: 64 << 20,
	})
	store.invalidateReady()
	if !store.Ready() {
		t.Fatal("empty store is not ready")
	}
	if _, err := store.Create(testEnvelope(), time.Hour, testProof()); err != nil {
		t.Fatalf("create: %v", err)
	}
	store.invalidateReady()
	if store.Ready() {
		t.Fatal("Ready ignored MAX_SECRETS")
	}
}

func TestValkeyReceiptRetentionAfterTerminalState(t *testing.T) {
	store, _ := newValkeyTestStoreWith(t, StoreConfig{ReceiptGrace: time.Hour})
	ttl := 7 * 24 * time.Hour
	before := time.Now()

	revoked, err := store.Create(testEnvelope(), ttl, testProof())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revoke(revoked.SecretID, revoked.ReceiptToken); err != nil {
		t.Fatal(err)
	}
	view, err := store.Receipt(revoked.SecretID, revoked.ReceiptToken)
	if err != nil {
		t.Fatal(err)
	}
	if view.ReceiptExpiresAt < before.Add(ttl+time.Hour).UnixMilli()-2000 {
		t.Fatalf("revoked receipt expiry = %d, want about ttl+grace", view.ReceiptExpiresAt)
	}

	burned, err := store.Create(testEnvelope(), ttl, testProof())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(burned.SecretID, testProof()); err != nil {
		t.Fatal(err)
	}
	view, err = store.Receipt(burned.SecretID, burned.ReceiptToken)
	if err != nil {
		t.Fatal(err)
	}
	if view.ReceiptExpiresAt < before.Add(ttl+time.Hour).UnixMilli()-2000 {
		t.Fatalf("burned receipt expiry = %d, want about ttl+grace", view.ReceiptExpiresAt)
	}
}

func TestValkeyStatsTrackLiveIndexes(t *testing.T) {
	store, _ := newValkeyTestStoreWith(t, StoreConfig{ReceiptGrace: time.Hour})
	burned, err := store.Create(testEnvelope(), time.Hour, testProof())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(testEnvelope(), time.Hour, testProof()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(burned.SecretID, testProof()); err != nil {
		t.Fatal(err)
	}
	stats := store.Stats()
	if stats.Secrets != 1 || stats.Receipts != 2 {
		t.Fatalf("stats = %+v, want 1 live secret and 2 receipts", stats)
	}
}
