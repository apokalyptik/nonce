package nonce

import (
	"log"
	"testing"
	"time"
)

func TestBasicUsage(t *testing.T) {
	store, err := New()
	if err != nil {
		t.Fatal(err)
	}
	store.Timeout(time.Duration(25 * time.Millisecond))
	if store.Verify("", "test") {
		t.Errorf("Expected Verify on invalid key to return false")
	}
	if store.Peek("", "test") {
		t.Errorf("Expected Peek on invalid key to return false")
	}
	n := store.Nonce("test")
	if !store.Peek(n, "test") {
		t.Errorf("Expected Peek on valid key to return true")
	}
	if !store.Peek(n, "test") {
		t.Errorf("Expected second Peek on valid key to return true")
	}
	if !store.Verify(n, "test") {
		t.Errorf("Expected Verify on valid key to return true")
	}
	if store.Verify(n, "test") {
		t.Errorf("Expected second Verify on once valid key to return false")
	}
	n = store.Nonce("test2")
	if _, ok := store.nonces[n]; !ok {
		t.Errorf("Expected valid nonce to still exist")
	}
	time.Sleep(time.Duration(26 * time.Millisecond))
	if store.Verify(n, "test") {
		t.Errorf("Expected second Verify on valid but expired key to return false")
	}
	if _, ok := store.nonces[n]; !ok {
		t.Errorf("Expected expired but non-cleaned up nonce to still exist")
	}
	time.Sleep(time.Duration(126 * time.Millisecond))
	if _, ok := store.nonces[n]; ok {
		t.Errorf("Expected expired nonce to have been cleaned up")
	}
	s2, _ := New()
	if s2.salt == store.salt {
		log.Printf("Expected two stores to contain unique, random, salts")
	}
}
