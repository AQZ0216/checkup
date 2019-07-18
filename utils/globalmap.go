package utils

import (
	"sync"
)

// https://blog.golang.org/go-maps-in-action#TOC_6.

type single struct {
	mu     sync.Mutex
	values map[string]string
}

var globalmap = single{
	values: make(map[string]string),
}

func GlobalCacheGetExistence(key string) bool {
	globalmap.mu.Lock()
	defer globalmap.mu.Unlock() // do after return, to unlock
	_, prs := globalmap.values[key]
	return prs
}

func GlobalCacheGetString(key string) string {
	globalmap.mu.Lock()
	defer globalmap.mu.Unlock()
	result := globalmap.values[key]
	return result
}

func GlobalCacheSetString(key string, value string) {
	globalmap.mu.Lock()
	defer globalmap.mu.Unlock()
	globalmap.values[key] = value
	return
}

func GlobalCacheClear() {
	globalmap.mu.Lock()
	defer globalmap.mu.Unlock()
	globalmap.values = nil
	globalmap.values = make(map[string]string)
	return
}
