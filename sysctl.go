package icmp_tun

import (
	"errors"
	"io/ioutil"
	"runtime"
	"strings"
)

func sysctlCheckOS() error {
	switch runtime.GOOS {
	case "linux", "android":
		return nil
	default:
		return errors.New("/proc/sys/ not available")
	}
}

func SysctlGet(key string) (val []byte, err error) {
	if err = sysctlCheckOS(); err != nil {
		return
	}
	file := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	return ioutil.ReadFile(file)
}

func SysctlSet(key string, val []byte) (err error) {
	if err = sysctlCheckOS(); err != nil {
		return
	}
	file := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	return ioutil.WriteFile(file, val, 0o777)
}
