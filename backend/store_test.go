package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func testProof() [32]byte {
	return sha256.Sum256([]byte("test-proof"))
}

func testEnvelope() validatedEnvelope {
	return validatedEnvelope{
		IV:         bytes.Repeat([]byte{0x11}, 12),
		Ciphertext: bytes.Repeat([]byte{0x22}, 40),
		Tag:        bytes.Repeat([]byte{0x33}, 16),
		MaxViews:   1,
	}
}

func newTestStore(clock *fakeClock) *Store {
	return NewStore(StoreConfig{
		MaxSecrets:    10,
		MaxTotalBytes: 1 << 20,
		ReceiptGrace:  time.Hour,
		Now:           clock.Now,
	})
}

func TestStoreCreateChallengeConsumeReceipt(t *testing.T) {
	clock := newFakeClock()
	store := newTestStore(clock)
	defer store.Close()

	created, err := store.Create(testEnvelope(), 10*time.Minute, testProof())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !validateSecretID(created.SecretID) {
		t.Fatalf("invalid secret id %q", created.SecretID)
	}
	if !validateToken(created.ReceiptToken, 32) {
		t.Fatalf("invalid receipt token")
	}
	if created.ExpiresAt != clock.Now().Add(10*time.Minute).UnixMilli() {
		t.Fatalf("unexpected expiry %d", created.ExpiresAt)
	}

	record := store.records[created.SecretID]
	if record == nil {
		t.Fatal("secret was not stored")
	}
	wantBytes := record.byteSize()
	if stats := store.Stats(); stats.TotalBytes != wantBytes {
		t.Fatalf("total bytes = %d, want %d", stats.TotalBytes, wantBytes)
	}
	originalIV := append([]byte(nil), record.iv...)

	info, err := store.Challenge(created.SecretID)
	if err != nil || info.MaxViews != 1 {
		t.Fatalf("challenge failed: %+v %v", info, err)
	}
	if events := store.receipts[created.SecretID].events; len(events) != 2 || events[1].Type != eventLinkOpened {
		t.Fatalf("unexpected events after challenge: %+v", events)
	}
	if opens := store.receipts[created.SecretID].opens; opens != 1 {
		t.Fatalf("opens after first challenge = %d, want 1", opens)
	}
	if _, err := store.Challenge(created.SecretID); err != nil {
		t.Fatal("second challenge failed")
	}
	receipt := store.receipts[created.SecretID]
	if len(receipt.events) != 2 {
		t.Fatalf("second challenge appended an event: %+v", receipt.events)
	}
	if receipt.opens != 2 || receipt.lastOpenedAt.IsZero() {
		t.Fatalf("second challenge opens=%d lastOpenedAt=%v", receipt.opens, receipt.lastOpenedAt)
	}

	consumed, err := store.Consume(created.SecretID, testProof())
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if consumed.Envelope.Ciphertext != base64.RawURLEncoding.EncodeToString(testEnvelope().Ciphertext) {
		t.Fatalf("unexpected ciphertext")
	}
	if !validateToken(consumed.ViewToken, 32) {
		t.Fatalf("invalid view token")
	}
	if _, exists := store.records[created.SecretID]; exists {
		t.Fatal("secret still present after consume")
	}
	if !allZero(record.iv) || !allZero(record.ciphertext) || !allZero(record.tag) || !allZero(record.proofHash[:]) {
		t.Fatal("secret buffers were not zeroed")
	}
	if allZero(originalIV) {
		t.Fatal("test setup error: original copy was zeroed")
	}
	if stats := store.Stats(); stats.Secrets != 0 || stats.TotalBytes != 0 {
		t.Fatalf("stats after consume: records=%d bytes=%d", stats.Secrets, stats.TotalBytes)
	}
	if _, err := store.Consume(created.SecretID, testProof()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("second consume error = %v, want unavailable", err)
	}

	if ok, err := store.ConfirmDecrypted(created.SecretID, "wrong"); err != nil || ok {
		t.Fatal("accepted an incorrect view token")
	}
	if ok, err := store.ConfirmDecrypted(created.SecretID, consumed.ViewToken); err != nil || !ok {
		t.Fatal("rejected the correct view token")
	}
	if ok, err := store.ConfirmDecrypted(created.SecretID, consumed.ViewToken); err != nil || !ok {
		t.Fatal("decrypted confirmation should be idempotent")
	}

	if _, err := store.Receipt(created.SecretID, "wrong"); err != nil {
		t.Fatalf("wrong receipt token errored: %v", err)
	}
	view, err := store.Receipt(created.SecretID, created.ReceiptToken)
	if err != nil || view.SecretID == "" {
		t.Fatalf("receipt not returned: %v", err)
	}
	if view.State != stateBurned || !view.Decrypted || view.BurnedAt == 0 {
		t.Fatalf("unexpected receipt: %+v", view)
	}
	want := []string{eventCreated, eventLinkOpened, eventDecryptAttempted, eventBurned, eventDecrypted}
	if len(view.Events) != len(want) {
		t.Fatalf("events = %+v", view.Events)
	}
	for i, eventType := range want {
		if view.Events[i].Type != eventType {
			t.Fatalf("event %d = %q, want %q", i, view.Events[i].Type, eventType)
		}
	}
}

func TestStoreExpiryAndReceiptRetention(t *testing.T) {
	clock := newFakeClock()
	store := newTestStore(clock)
	defer store.Close()

	created, err := store.Create(testEnvelope(), 10*time.Minute, testProof())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	record := store.records[created.SecretID]
	clock.Advance(10*time.Minute + time.Millisecond)

	if info, err := store.Challenge(created.SecretID); err != nil || info.SecretID != "" {
		t.Fatalf("expired challenge returned %+v, %v", info, err)
	}
	if _, exists := store.records[created.SecretID]; exists {
		t.Fatal("expired secret was not removed")
	}
	if !allZero(record.iv) || !allZero(record.ciphertext) || !allZero(record.tag) || !allZero(record.proofHash[:]) {
		t.Fatal("expired secret buffers were not zeroed")
	}
	view, err := store.Receipt(created.SecretID, created.ReceiptToken)
	if err != nil || view.State != stateExpired {
		t.Fatalf("expired receipt: %+v %v", view, err)
	}
	if view.Events[len(view.Events)-1].Type != eventExpired {
		t.Fatalf("expired event missing: %+v", view.Events)
	}
	clock.Advance(time.Minute)
	store.Sweep()
	view, err = store.Receipt(created.SecretID, created.ReceiptToken)
	if err != nil || view.SecretID == "" {
		t.Fatal("receipt vanished before its retention window")
	}
	expiredEvents := 0
	for _, event := range view.Events {
		if event.Type == eventExpired {
			expiredEvents++
		}
	}
	if expiredEvents != 1 {
		t.Fatalf("expired emitted %d times", expiredEvents)
	}

	clock.Advance(2 * time.Hour)
	store.Sweep()
	if view, err := store.Receipt(created.SecretID, created.ReceiptToken); err != nil || view.SecretID != "" {
		t.Fatal("receipt survived its retention window")
	}
	if receipts := store.Stats().Receipts; receipts != 0 {
		t.Fatalf("receipt still counted: %d", receipts)
	}
}

func TestStoreCapacityAndTotalBytes(t *testing.T) {
	clock := newFakeClock()
	store := NewStore(StoreConfig{
		MaxSecrets:    1,
		MaxTotalBytes: 1 << 20,
		ReceiptGrace:  time.Hour,
		Now:           clock.Now,
	})
	defer store.Close()

	if _, err := store.Create(testEnvelope(), time.Minute, testProof()); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := store.Create(testEnvelope(), time.Minute, testProof()); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("second create error = %v, want full", err)
	}

	small := NewStore(StoreConfig{
		MaxSecrets:    10,
		MaxTotalBytes: 1,
		ReceiptGrace:  time.Hour,
		Now:           clock.Now,
	})
	defer small.Close()
	if _, err := small.Create(testEnvelope(), time.Minute, testProof()); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("byte cap error = %v, want full", err)
	}
}

func TestStoreConcurrentConsumeIsAtomic(t *testing.T) {
	clock := newFakeClock()
	store := newTestStore(clock)
	defer store.Close()

	created, err := store.Create(testEnvelope(), 10*time.Minute, testProof())
	if err != nil {
		t.Fatalf("create: %v", err)
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

func TestStoreReceiptCapacityEvictsTerminalReceipts(t *testing.T) {
	clock := newFakeClock()
	store := NewStore(StoreConfig{
		MaxSecrets:    10,
		MaxReceipts:   2,
		MaxTotalBytes: 1 << 20,
		ReceiptGrace:  time.Hour,
		Now:           clock.Now,
	})
	defer store.Close()

	first, err := store.Create(testEnvelope(), time.Minute, testProof())
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Create(testEnvelope(), time.Minute, testProof())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(testEnvelope(), time.Minute, testProof()); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("create with all live receipts = %v, want full", err)
	}
	if _, err := store.Consume(first.SecretID, testProof()); err != nil {
		t.Fatal(err)
	}
	third, err := store.Create(testEnvelope(), time.Minute, testProof())
	if err != nil {
		t.Fatalf("create after terminal receipt: %v", err)
	}
	if view, err := store.Receipt(first.SecretID, first.ReceiptToken); err != nil || view.SecretID != "" {
		t.Fatal("oldest terminal receipt was not evicted")
	}
	if view, err := store.Receipt(second.SecretID, second.ReceiptToken); err != nil || view.SecretID == "" {
		t.Fatal("live receipt was evicted")
	}
	if view, err := store.Receipt(third.SecretID, third.ReceiptToken); err != nil || view.SecretID == "" {
		t.Fatal("new receipt missing")
	}
	if receipts := store.receipts; len(receipts) > 2 {
		t.Fatalf("receipt cap exceeded: %d", len(receipts))
	}
}

func TestStoreSweepExpiresAndWipesWithoutAccess(t *testing.T) {
	clock := newFakeClock()
	store := newTestStore(clock)
	defer store.Close()

	created, err := store.Create(testEnvelope(), 10*time.Minute, testProof())
	if err != nil {
		t.Fatal(err)
	}
	record := store.records[created.SecretID]
	clock.Advance(10*time.Minute + time.Millisecond)
	store.Sweep()

	if _, exists := store.records[created.SecretID]; exists {
		t.Fatal("expired secret survived sweep")
	}
	if !allZero(record.iv) || !allZero(record.ciphertext) || !allZero(record.tag) || !allZero(record.proofHash[:]) {
		t.Fatal("sweep did not zero expired secret buffers")
	}
	if view, err := store.Receipt(created.SecretID, created.ReceiptToken); err != nil || view.State != stateExpired {
		t.Fatalf("expired receipt: %+v %v", view, err)
	}
}

func TestStoreRevokeWipesSecret(t *testing.T) {
	clock := newFakeClock()
	store := newTestStore(clock)
	defer store.Close()

	created, err := store.Create(testEnvelope(), time.Minute, testProof())
	if err != nil {
		t.Fatal(err)
	}
	record := store.records[created.SecretID]
	result, err := store.Revoke(created.SecretID, created.ReceiptToken)
	if err != nil || result.State != stateRevoked {
		t.Fatalf("revoke = %+v %v", result, err)
	}
	if _, exists := store.records[created.SecretID]; exists {
		t.Fatal("revoked secret still present")
	}
	if !allZero(record.iv) || !allZero(record.ciphertext) || !allZero(record.tag) || !allZero(record.proofHash[:]) {
		t.Fatal("revoke did not zero secret buffers")
	}
}

func TestStoreReceiptRetentionWipesHashes(t *testing.T) {
	clock := newFakeClock()
	store := newTestStore(clock)
	defer store.Close()

	created, err := store.Create(testEnvelope(), time.Minute, testProof())
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := store.Consume(created.SecretID, testProof())
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.ConfirmDecrypted(created.SecretID, consumed.ViewToken); err != nil || !ok {
		t.Fatal("confirm decrypted")
	}
	receipt := store.receipts[created.SecretID]
	clock.Advance(2 * time.Hour)
	store.Sweep()
	if _, exists := store.receipts[created.SecretID]; exists {
		t.Fatal("expired receipt survived sweep")
	}
	if !allZero(receipt.tokenHash[:]) || !allZero(receipt.viewTokenHash[:]) {
		t.Fatal("receipt hashes were not zeroed")
	}
	if receipt.events != nil {
		t.Fatal("receipt events were not cleared")
	}
}

func TestStoreCloseZeroesOutstandingData(t *testing.T) {
	clock := newFakeClock()
	store := newTestStore(clock)
	created, err := store.Create(testEnvelope(), time.Minute, testProof())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	record := store.records[created.SecretID]
	receipt := store.receipts[created.SecretID]
	store.Close()
	if !allZero(record.iv) || !allZero(record.ciphertext) || !allZero(record.tag) || !allZero(record.proofHash[:]) {
		t.Fatal("close did not zero secret buffers")
	}
	if !allZero(receipt.tokenHash[:]) || !allZero(receipt.viewTokenHash[:]) {
		t.Fatal("close did not zero receipt hashes")
	}
	if stats := store.Stats(); stats.Secrets != 0 || stats.TotalBytes != 0 || stats.Receipts != 0 {
		t.Fatalf("close left state: %d %d %d", stats.Secrets, stats.TotalBytes, stats.Receipts)
	}
}

func TestStoreInvalidTokensAndReceiptEvents(t *testing.T) {
	clock := newFakeClock()
	store := newTestStore(clock)
	defer store.Close()

	created, err := store.Create(testEnvelope(), time.Minute, testProof())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ok, err := store.ConfirmDecrypted(created.SecretID, "not-a-token"); err != nil || ok {
		t.Fatal("confirm accepted a token before a read")
	}
	view, err := store.Receipt(created.SecretID, created.ReceiptToken)
	if err != nil || view.State != stateAvailable {
		t.Fatalf("unexpected initial receipt: %+v", view)
	}
	if len(view.Events) != 1 || view.Events[0].Type != eventCreated {
		t.Fatalf("initial events: %+v", view.Events)
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
