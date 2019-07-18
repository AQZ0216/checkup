package utils

import (
	"testing"
)

func TestGlobalStringSetAndGet(t *testing.T) {
	str1 := GlobalCacheGetString("123")
	t.Logf("str1:%s", str1)
	GlobalCacheSetString("123", "hello")
	str2 := GlobalCacheGetString("123")
	t.Logf("str2:%s", str2)
	if str2 != "hello" {
		t.Fatalf("str2:%s", str2)
	}
	GlobalCacheClear()
	str3 := GlobalCacheGetString("123")
	t.Logf("str3:%s", str3)
	if str3 != "" {
		t.Fatalf("str3:%s", str3)
	}

}
