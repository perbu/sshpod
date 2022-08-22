package sshd

import (
	"encoding/hex"
	"github.com/gliderlabs/ssh"
)

// There is a slight mismatch between Gliderlabs ssh and Go ssh. This code glues them together.
// https://github.com/gliderlabs/ssh/pull/124

type gContext ssh.Context
type gContextWrapper struct{ gContext }

func (s *gContextWrapper) ClientVersion() []byte { return []byte(s.gContext.ClientVersion()) }
func (s *gContextWrapper) ServerVersion() []byte { return []byte(s.gContext.ServerVersion()) }
func (s *gContextWrapper) SessionID() []byte {
	dec, _ := hex.DecodeString(s.gContext.SessionID())
	return dec
}
