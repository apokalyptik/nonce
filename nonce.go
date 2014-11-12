// nonce provides you with a small set of tools for working with an in-memory
// nonce store.  Typically you would create a nonce in your application to help
// validate the authenticity of requested actions as well as prevent certain
// kinds of attacks, such as reply attacks.
//
// An example use case would be for a web app which allows users to interract
// with widgets.  In this case we want to create a nonce which we can later use
// to validate that user ID 123 does, in fact, want to delete widget "foo"
//
//    store, _ := nonce.New()
//    nonce := store.Nonce("123:foo:delete")
//    // ...
//    if store.Verify(nonce, "123:foo:delete") {
//        // delete the widget
//    } else {
//        // the nonce has expired,
//        // or the action has already occured,
//        // or the user was being tricked into doing dsomething gainst their
//        //     wishes such as a CSRF attack
//        // or the user is poking their nose around your API and trying to
//        //     figure our how your app works.  Sometimes the worst case is
//        //     just paranoia :)
//    }
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

// Store provides a non-persisted in-memory store for, as well as functions to
// create and verify, nonces.
type Store struct {
	m             sync.RWMutex
	salt          string
	expiration    time.Duration
	nonces        map[string]time.Time
	h             hash.Hash
	newExpiration chan struct{}
}

// Timeout allows you to specify how long nonces are valid for.  This function
// is normally only called directly after creating the store, but before using
// it.  Updating this value has the side effect of updating how often the go
// map (which actually holds all of the nonces internally) is scanned for
// expired nonces.
func (s *Store) Timeout(t time.Duration) *Store {
	s.expiration = t
	s.newExpiration <- struct{}{}
	return s
}

// Salt allows you to specify the salt used internally while creating nonces.
// This should only be done after creating the store but before using it as
// changing this value will immediately invalidate all existing nonces
// regardless of their existence or expiration
func (s *Store) Salt(salt string) *Store {
	s.salt = salt
	return s
}

// Nonce creates a nonce for the provided action.  Given the resulting string
// and the original action string you can use *store.Verify() and *store.Peek()
// at a later time to validate the nonce.
func (s *Store) Nonce(action string) string {
	s.m.Lock()
	defer s.m.Unlock()
	t := time.Now().Add(s.expiration)
	h := s.hash(action, t)
	s.nonces[h] = t
	return h
}

// Verify validates a nonce against an action.  It checkes that all of the
// following are true: the nonce exists, the nonce has not expired, the nonce
// is for the action provided.
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

// Peek allows you to see if a valid matching nonce exists without actually
// removing it from the store.
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
		c := <-time.After(5 * s.expiration)
		select {
		case when := <-c:
			s.m.Lock()
			for k, v := range s.nonces {
				if when.After(v) {
					delete(s.nonces, k)
				}
			}
			s.m.Unlock()
		case <-s.newExpiration:
			continue
		}
	}
}

// New returns a new nonce store.  You should always use this function instead
// of var something = &nonce.Store{} because it sets defaults, and begins the
// goroutine responsible for cleaning up expired nonces from the store.
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
