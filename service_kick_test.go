package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type nopHandler struct{}

func (nopHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
}

// open authenticates one session with password pw and returns a channel that
// receives once the server side of that session has ended.
func open(t *testing.T, s *Service, pw string) (net.Conn, chan error) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.NewConnection(context.Background(), server, M.Socksaddr{}, nil) }()
	sum := sha256.Sum256([]byte(pw))
	hello := append(sum[:], 0, 0) // 2-byte padding length 0
	binary.BigEndian.PutUint16(hello[32:], 0)
	if _, err := client.Write(hello); err != nil {
		t.Fatal(err)
	}
	go func() { // drain whatever the server session writes (settings, etc.)
		b := make([]byte, 4096)
		for {
			if _, err := client.Read(b); err != nil {
				return
			}
		}
	}()
	return client, done
}

func waitSessions(t *testing.T, s *Service, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for s.SessionCount() != n {
		if time.Now().After(deadline) {
			t.Fatalf("sessions = %d, want %d", s.SessionCount(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func ended(done chan error, within time.Duration) bool {
	select {
	case <-done:
		return true
	case <-time.After(within):
		return false
	}
}

func TestUpdateUsersClosesStaleSessions(t *testing.T) {
	s, err := NewService(ServiceConfig{
		PaddingScheme: padding.DefaultPaddingScheme,
		Users:         []User{{Name: "a", Password: "pa"}, {Name: "b", Password: "pb"}},
		Handler:       nopHandler{},
		Logger:        logger.NOP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ca, doneA := open(t, s, "pa")
	defer ca.Close()
	cb, doneB := open(t, s, "pb")
	defer cb.Close()
	waitSessions(t, s, 2)

	// a is removed (e.g. over quota): its live session must end, b's must not.
	s.UpdateUsers([]User{{Name: "b", Password: "pb"}, {Name: "c", Password: "pc"}})
	if !ended(doneA, 2*time.Second) {
		t.Fatal("removed user's session is still open")
	}
	if ended(doneB, 200*time.Millisecond) {
		t.Fatal("a kept user's session was closed")
	}
	waitSessions(t, s, 1)

	// a removed user cannot open a new session.
	_, doneA2 := open(t, s, "pa")
	if !ended(doneA2, 2*time.Second) {
		t.Fatal("removed user opened a new session")
	}
	waitSessions(t, s, 1)

	// b's password is reset: the session opened with the old one must end.
	s.UpdateUsers([]User{{Name: "b", Password: "pb-new"}})
	if !ended(doneB, 2*time.Second) {
		t.Fatal("session with the old password survived a password reset")
	}
	waitSessions(t, s, 0)

	// the new password works.
	cb2, doneB2 := open(t, s, "pb-new")
	defer cb2.Close()
	waitSessions(t, s, 1)
	if ended(doneB2, 200*time.Millisecond) {
		t.Fatal("session with the new password was closed")
	}
}
