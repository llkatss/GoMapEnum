package utils

import (
	"GoMapEnum/src/logger"
	"errors"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/net/proxy"
)

// BaseOptions is the common options for the module
type BaseOptions struct {
	Users         string
	UsernameList  []string
	Passwords     string
	Thread        int
	Log           *logger.Logger
	NoBruteforce  bool
	StopOnLockout bool
	Sleep         int
	Target        string
	ThrotLimit    int
	ThrotAction   string
	ThrotAdd      bool
	ErrorAdd      bool
	ErrorLimit    int
	ErrorAction   string
	LogFile       string
	CheckIfValid  bool
	ProxyHTTP     func(*http.Request) (*url.URL, error)
	ProxyFile     string
	ProxyTCP      proxy.Dialer
	Mutex         sync.Mutex
	ReqMultiplier int
}

// ErrLockout is the error to returned when an account is locked
var ErrLockout = errors.New("account is locked")
