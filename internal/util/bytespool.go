package util

import "sync"

var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, 64*1024); return &b }}

// GetBuf returns a pooled byte slice with len=0, cap≥64KiB. Use PutBuf to
// release. Caller must not retain the slice after Put.
func GetBuf() *[]byte { return bufPool.Get().(*[]byte) }

// PutBuf returns the slice to the pool with len reset to 0.
func PutBuf(b *[]byte) {
	if b == nil {
		return
	}
	*b = (*b)[:0]
	bufPool.Put(b)
}
