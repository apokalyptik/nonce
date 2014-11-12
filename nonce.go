package nonce

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"hash"
	"io"
	"sync"
	"time"
)

type Store struct {
	m          sync.RWMutex
	salt       string
	expiration time.Duration
	nonces     map[string]time.Time
	h          hash.Hash
}

func (s *Store) Timeout(t time.Duration) *Store {
	s.expiration = t
	return s
}

func (s *Store) Salt(salt string) *Store {
	s.salt = salt
	return s
}

func (s *Store) Nonce(action string) string {
	s.m.Lock()
	defer s.m.Unlock()
	t := time.Now().Add(s.expiration)
	h := s.hash(action, t)
	s.nonces[h] = t
	return h
}

func (s *Store) Verify(nonce, action string) bool {
	s.m.RLock()
	defer s.m.RUnlock()
	if t, ok := s.nonces[nonce]; ok {
		if time.Now().After(t) {
			return false
		}
		if s.hash(action, t) == nonce {
			delete(s.nonces, nonce)
			return true
		}
	}
	return false
}

func (s *Store) Peek(nonce, action string) bool {
	s.m.RLock()
	defer s.m.RUnlock()
	if t, ok := s.nonces[nonce]; ok {
		if time.Now().After(t) {
			return false
		}
		if s.hash(action, t) == nonce {
			return true
		}
	}
	return false
}

func (s *Store) hash(action string, t time.Time) string {
	s.h.Reset()
	io.WriteString(s.h, fmt.Sprintf("%s:%s:%s", t.String(), action, s.salt))
	var theHash = s.h.Sum(nil)
	var rval = make([]byte, len(theHash))
	for k, v := range theHash {
		rval[k] = v
	}
	return string(rval)
}

func (s *Store) mindExpiration() {
	for {
		when := <-time.After(5 * s.expiration)
		s.m.Lock()
		for k, v := range s.nonces {
			if when.After(v) {
				delete(s.nonces, k)
			}
		}
		s.m.Unlock()
	}
}

func New() (*Store, error) {
	var randBytes = make([]byte, 20)
	if _, e := rand.Read(randBytes); e != nil {
		return nil, e
	}
	var rval = &Store{
		expiration: time.Duration(30 * time.Minute),
		nonces:     map[string]time.Time{},
		salt:       string(randBytes),
		h:          sha1.New(),
	}
	go rval.mindExpiration()
	return rval, nil
}
