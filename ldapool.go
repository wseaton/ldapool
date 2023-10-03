package ldapool

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LdapConfig ldap conn config
type LdapConfig struct {
	Url     string
	BaseDN  string
	MaxOpen int
}

// Connection pool
type LdapConnPool struct {
	mu       sync.Mutex
	conns    []*ldap.Conn
	reqConns map[uint64]chan *ldap.Conn
	openConn int
	maxOpen  int
	DsName   string
}

type LdapPoolManager struct {
	ldapool     *LdapConnPool
	ldapInit    bool
	ldapInitOne sync.Once
}

var ldapManager = &LdapPoolManager{}

func Open(conf LdapConfig) (*ldap.Conn, error) {
	// Initialize the connection first
	ldapManager.InitLDAP(conf)
	// Get LDAP connection
	conn, err := ldapManager.GetLDAPConn(conf)
	defer ldapManager.PutLDAPConn(conn)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Initialize connection
func (manager *LdapPoolManager) InitLDAP(conf LdapConfig) {
	if manager.ldapInit {
		return
	}

	manager.ldapInitOne.Do(func() {
		manager.ldapInit = true
	})

	ldapConn, err := ldap.DialURL(conf.Url, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}))
	if err != nil {
		panic(fmt.Sprintf("Init Ldap Connection Failed: %v", err))
	}

	// Global variable assignment
	manager.ldapool = &LdapConnPool{
		conns:    make([]*ldap.Conn, 0),
		reqConns: make(map[uint64]chan *ldap.Conn),
		openConn: 0,
		maxOpen:  conf.MaxOpen,
	}
	manager.PutLDAPConn(ldapConn)
}

// GetLDAPConn Get LDAP connection
func (manager *LdapPoolManager) GetLDAPConn(conf LdapConfig) (*ldap.Conn, error) {
	return manager.ldapool.GetConnection(conf)
}

// PutLDAPConn Put back the LDAP connection
func (manager *LdapPoolManager) PutLDAPConn(conn *ldap.Conn) {
	manager.ldapool.PutConnection(conn)
}

// GetConnection
func (lcp *LdapConnPool) GetConnection(conf LdapConfig) (*ldap.Conn, error) {
	lcp.mu.Lock()
	// Determine whether there is a connection in the current connection pool
	connNum := len(lcp.conns)
	if connNum > 0 {
		lcp.openConn++
		conn := lcp.conns[0]
		copy(lcp.conns, lcp.conns[1:])
		lcp.conns = lcp.conns[:connNum-1]

		lcp.mu.Unlock()
		// If the connection has been closed, get the connection again
		if conn.IsClosing() {
			return initLDAPConn(conf)
		}
		return conn, nil
	}

	// When the existing connection pool is empty and the maximum connection limit is currently exceeded
	if lcp.maxOpen != 0 && lcp.openConn > lcp.maxOpen {
		// Create a waiting queue
		req := make(chan *ldap.Conn, 1)
		reqKey := lcp.nextRequestKeyLocked()
		lcp.reqConns[reqKey] = req
		lcp.mu.Unlock()

		// Waiting for request for return
		return <-req, nil
	} else {
		lcp.openConn++
		lcp.mu.Unlock()
		return initLDAPConn(conf)
	}
}

func (lcp *LdapConnPool) PutConnection(conn *ldap.Conn) {
	lcp.mu.Lock()
	defer lcp.mu.Unlock()

	// First determine whether there is a waiting queue
	if num := len(lcp.reqConns); num > 0 {
		var req chan *ldap.Conn
		var reqKey uint64
		for reqKey, req = range lcp.reqConns {
			break
		}
		delete(lcp.reqConns, reqKey)
		req <- conn
		return
	} else {
		lcp.openConn--
		if !conn.IsClosing() {
			lcp.conns = append(lcp.conns, conn)
		}
	}
}

// nextRequestKeyLocked Get the next request token
func (lcp *LdapConnPool) nextRequestKeyLocked() uint64 {
	for {
		reqKey := rand.Uint64()
		if _, ok := lcp.reqConns[reqKey]; !ok {
			return reqKey
		}
	}
}

// initLDAPConn
func initLDAPConn(conf LdapConfig) (*ldap.Conn, error) {
	ldap, err := ldap.DialURL(conf.Url, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}))
	if err != nil {
		return nil, err
	}
	return ldap, err
}
