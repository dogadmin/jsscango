//go:build windows

package autotune

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX struct. Field layout
// and ordering must match the Microsoft definition exactly; the call
// fails (returns 0) if dwLength isn't the struct size.
//
//	typedef struct _MEMORYSTATUSEX {
//	  DWORD     dwLength;
//	  DWORD     dwMemoryLoad;
//	  DWORDLONG ullTotalPhys;
//	  DWORDLONG ullAvailPhys;
//	  DWORDLONG ullTotalPageFile;
//	  DWORDLONG ullAvailPageFile;
//	  DWORDLONG ullTotalVirtual;
//	  DWORDLONG ullAvailVirtual;
//	  DWORDLONG ullAvailExtendedVirtual;
//	} MEMORYSTATUSEX;
type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

// We dynamically resolve GlobalMemoryStatusEx via the Win32 kernel32.dll
// because x/sys/windows doesn't expose a typed wrapper for it in this
// vendored version. NewLazySystemDLL guards against DLL-preload attacks
// (only loads from %SystemRoot%\System32) and is the recommended path
// for system-DLL calls in golang.org/x/sys/windows.
var (
	modkernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
)

// sysTotalRAM queries Win32 GlobalMemoryStatusEx and returns total
// installed physical RAM in bytes. Returns (0, err) on any failure;
// the caller (Detect) treats a zero RAM as "unknown" and falls back to
// the CPU-only gate.
func sysTotalRAM() (uint64, error) {
	var s memoryStatusEx
	s.dwLength = uint32(unsafe.Sizeof(s))
	r1, _, e1 := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&s)))
	if r1 == 0 {
		if e1 != nil {
			return 0, e1
		}
		return 0, fmt.Errorf("GlobalMemoryStatusEx returned 0")
	}
	return s.ullTotalPhys, nil
}
