package main

import "time"

// SecretStore is the persistence contract shared by the in-memory and Valkey
// implementations. All methods must be safe for concurrent callers.
type SecretStore interface {
	Create(env validatedEnvelope, ttl time.Duration, proofHash [32]byte) (CreateResult, error)
	Challenge(id string) (ChallengeInfo, error)
	Consume(id string, proofHash [32]byte) (ConsumeResult, error)
	Revoke(id, receiptToken string) (RevokeResult, error)
	ConfirmDecrypted(id, viewToken string) (bool, error)
	Receipt(id, receiptToken string) (ReceiptView, error)
	Sweep()
	Close()
	Stats() StoreStats
	Ready() bool
}
