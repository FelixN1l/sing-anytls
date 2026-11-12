package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Service struct {
	// mu guards users. Added by the milou fork: upstream's UpdateUsers
	// swapped s.users at runtime while NewConnection was reading it —
	// concurrent map access under Go's memory model. UpdateUsers now
	// takes the write lock; NewConnection snapshots under the read lock.
	mu              sync.RWMutex
	users           map[[32]byte]string
	// sessions holds the live session connections by the credential they
	// authenticated with (milou fork, 2026-11-10). The password is checked
	// once per session and every later stream rides on it, so a user removed
	// from the roster (over quota, expired, password reset) kept full service
	// until the client dropped the connection. UpdateUsers now closes the
	// sessions whose credential is no longer on the roster. Guarded by mu.
	sessions        map[[32]byte]map[net.Conn]struct{}
	padding         atomic.TypedValue[*padding.PaddingFactory]
	handler         N.TCPConnectionHandlerEx
	fallbackHandler N.TCPConnectionHandlerEx
	logger          logger.ContextLogger
}

type ServiceConfig struct {
	PaddingScheme   []byte
	Users           []User
	Handler         N.TCPConnectionHandlerEx
	FallbackHandler N.TCPConnectionHandlerEx
	Logger          logger.ContextLogger
}

type User struct {
	Name     string
	Password string
}

func NewService(config ServiceConfig) (*Service, error) {
	service := &Service{
		handler:         config.Handler,
		fallbackHandler: config.FallbackHandler,
		logger:          config.Logger,
		users:           make(map[[32]byte]string),
		sessions:        make(map[[32]byte]map[net.Conn]struct{}),
	}

	if service.handler == nil || service.logger == nil {
		return nil, os.ErrInvalid
	}

	for _, user := range config.Users {
		service.users[sha256.Sum256([]byte(user.Password))] = user.Name
	}

	if !padding.UpdatePaddingScheme(config.PaddingScheme, &service.padding) {
		return nil, errors.New("incorrect padding scheme format")
	}

	return service, nil
}

func (s *Service) UpdateUsers(users []User) {
	u := make(map[[32]byte]string)
	for _, user := range users {
		u[sha256.Sum256([]byte(user.Password))] = user.Name
	}
	// milou fork: swap the roster and pick the sessions it no longer covers
	// under one lock, so a session can't authenticate against the old roster
	// after the sweep (registration takes the same lock, see NewConnection).
	var stale []net.Conn
	s.mu.Lock()
	s.users = u
	for hash, conns := range s.sessions {
		if _, ok := u[hash]; ok {
			continue
		}
		for conn := range conns {
			stale = append(stale, conn)
		}
		delete(s.sessions, hash)
	}
	s.mu.Unlock()
	for _, conn := range stale {
		_ = conn.Close()
	}
	if len(stale) > 0 {
		s.logger.Info("anytls: closed ", len(stale), " session(s) of removed or re-keyed users")
	}
}

// SessionCount returns the number of live authenticated sessions (milou fork).
func (s *Service) SessionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, conns := range s.sessions {
		n += len(conns)
	}
	return n
}

// trackSession registers conn under its credential if that credential is on
// the current roster, and returns the user name and an untrack func. Check and
// registration happen under the write lock UpdateUsers holds while it sweeps.
func (s *Service) trackSession(hash [32]byte, conn net.Conn) (string, func(), bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[hash]
	if !ok {
		return "", nil, false
	}
	set := s.sessions[hash]
	if set == nil {
		set = make(map[net.Conn]struct{})
		s.sessions[hash] = set
	}
	set[conn] = struct{}{}
	return user, func() {
		s.mu.Lock()
		if set := s.sessions[hash]; set != nil {
			delete(set, conn)
			if len(set) == 0 {
				delete(s.sessions, hash)
			}
		}
		s.mu.Unlock()
	}, true
}

// NewConnection `conn` should be plaintext
func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	b := buf.NewPacket()
	defer b.Release()

	n, err := b.ReadOnceFrom(conn)
	if err != nil {
		return err
	}
	conn = bufio.NewCachedConn(conn, b)

	by, err := b.ReadBytes(32)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, err, onClose)
	}
	var passwordSha256 [32]byte
	copy(passwordSha256[:], by)
	// milou fork: check the credential and register the session in one step,
	// under the lock UpdateUsers sweeps with (see trackSession), so a later
	// roster change can close it.
	user, untrack, ok := s.trackSession(passwordSha256, conn)
	if !ok {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.New("unknown user password"), onClose)
	}
	defer untrack()
	ctx = auth.ContextWithUser(ctx, user)
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.Extend(err, "read padding length"), onClose)
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			b.Resize(0, n)
			return s.fallback(ctx, conn, source, E.Extend(err, "read padding"), onClose)
		}
	}

	session := session.NewServerSession(conn, func(stream *session.Stream) {
		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			s.logger.ErrorContext(ctx, "ReadAddrPort:", err)
			return
		}

		s.handler.NewConnectionEx(ctx, stream, source, destination, onClose)
	}, &s.padding, s.logger)
	session.Run()
	session.Close()
	return nil
}

func (s *Service) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}
