package main

import "sync"

type cache struct{ n int }

type store struct {
	mu sync.Mutex
	c  *cache
}

// lock takes the mutex and hands back the guarded value; unlock releases
// it.  The returned value is not a lock that must be released.
// Expected: no resource findings.
func (s *store) lock() *cache {
	s.mu.Lock()
	return s.c
}

func (s *store) unlock() {
	s.mu.Unlock()
}

func (s *store) count() int {
	c := s.lock()
	defer s.unlock()
	return c.n
}
