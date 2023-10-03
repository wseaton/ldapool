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
type ldapConnPool struct {
	mu       sync.Mutex
	conns    []*ldap.Conn
	reqConns map[uint64]chan *ldap.Conn
	openConn int
	maxOpen  int
	DsName   string
	config   LdapConfig
}

type LdapPoolManager struct {
	ldapool     *ldapConnPool
	ldapInit    bool
	ldapInitOne sync.Once
	closed      bool
	config      LdapConfig
}

// NewLdapPoolManager creates a new instance of LdapPoolManager
func NewLdapPoolManager(conf LdapConfig) (*LdapPoolManager, error) {
	manager := &LdapPoolManager{
		config: conf,
	}
	err := manager.initLDAP()
	if err != nil {
		return nil, err
	}
	return manager, nil
}

func (manager *LdapPoolManager) Open() (*ldap.Conn, error) {
	if !manager.ldapInit {
		return nil, fmt.Errorf("LDAP connection is not initialized")
	}
	return manager.GetConn()
}

// Initialize connection
func (manager *LdapPoolManager) initLDAP() error {
	if manager.ldapInit {
		return nil
	}

	manager.ldapInitOne.Do(func() {
		manager.ldapInit = true
	})

	ldapConn, err := ldap.DialURL(manager.config.Url, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}))
	if err != nil {
		return fmt.Errorf("init LDAP connection failed: %v", err)
	}

	// Global variable assignment
	manager.ldapool = &ldapConnPool{
		conns:    make([]*ldap.Conn, 0),
		reqConns: make(map[uint64]chan *ldap.Conn),
		openConn: 0,
		maxOpen:  manager.config.MaxOpen,
		config:   manager.config,
	}
	manager.PutConn(ldapConn)
	return nil
}

// Close all connections in the pool
func (manager *LdapPoolManager) Close() {
	manager.ldapool.mu.Lock()
	defer manager.ldapool.mu.Unlock()

	for _, conn := range manager.ldapool.conns {
		conn.Close()
	}
	manager.ldapool.conns = nil
	manager.ldapool.reqConns = nil
	manager.closed = true
}

// IsClosed checks if the manager has been closed
func (manager *LdapPoolManager) IsClosed() bool {
	manager.ldapool.mu.Lock()
	defer manager.ldapool.mu.Unlock()

	return manager.closed
}

// GetConn Get LDAP connection
func (manager *LdapPoolManager) GetConn() (*ldap.Conn, error) {
	return manager.ldapool.getConnection()
}

// PutConn Put back the LDAP connection
func (manager *LdapPoolManager) PutConn(conn *ldap.Conn) {
	manager.ldapool.putConnection(conn)
}

// getConnection
func (lcp *ldapConnPool) getConnection() (*ldap.Conn, error) {
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
			return initLDAPConn(lcp.config)
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
		return initLDAPConn(lcp.config)
	}
}

func (lcp *ldapConnPool) putConnection(conn *ldap.Conn) {
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
func (lcp *ldapConnPool) nextRequestKeyLocked() uint64 {
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
