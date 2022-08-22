package sshd

import (
	"bytes"
	"context"
	"fmt"
	log "github.com/celerway/chainsaw"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"net"
	"strconv"
	"strings"
)

type Server struct {
	server   *ssh.Server
	pubKey   ssh.PublicKey
	routerId int
	logger   log.Logger
	listener net.Listener
	port     int
	check    gossh.CertChecker
}

// New creates a new sshd server.
// Params:
// - signer - the private key
// - the public key that is allowed to connect. if this key has signed the cert logging in that will also do
// - addr - what to listen
func New(signer ssh.Signer, key ssh.PublicKey, routerId, port int, logger log.Logger) (*Server, error) {

	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %v", addr, err)
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port
	logger.Infof("sshd allocated listening socket on %v (requested %v) ", actualPort, port)

	app := &Server{
		pubKey:   key,
		routerId: routerId,
		logger:   logger,
		port:     actualPort,
		listener: listener,
	}
	app.check = gossh.CertChecker{
		IsUserAuthority: app.userAuthorityChecker,
	}

	app.server = &ssh.Server{
		PublicKeyHandler:         app.myPubKeyHandler,
		ConnectionFailedCallback: nil,
		Handler:                  app.sshHandler,
		HostSigners:              []ssh.Signer{signer},
	}
	return app, nil
}

func (app Server) Run(ctx context.Context) error {
	app.logger.Infof("Starting Ssh server for ID %d on: :%d", app.routerId, app.port)

	go func() {
		<-ctx.Done()
		app.server.Close()
	}()
	err := app.server.Serve(app.listener)
	if err != nil && ctx.Err() == nil {
		return fmt.Errorf("error running server: %w", err)
	}
	return nil
}

func (app Server) Port() int {
	return app.port
}

func (a Server) sshHandler(s ssh.Session) {
	defer s.Close()
	if s.RawCommand() != "" {
		io.WriteString(s, "raw commands are not supported")
		return
	}
	io.WriteString(s, fmt.Sprintf("Welcome to my own ssh daemon, %s\n", s.User()))

	term := terminal.NewTerminal(s, fmt.Sprintf("%s (id: %d)> ", s.User(), a.routerId))
	pty, winCh, isPty := s.Pty()
	if isPty {
		fmt.Println("PTY term", pty.Term)
		go func() {
			for chInfo := range winCh {
				fmt.Println("winch:", chInfo)
				err := term.SetSize(chInfo.Width, chInfo.Height)
				if err != nil {
					fmt.Println("winch error:", err)
				}
			}
		}()
	}

	for {
		line, err := term.ReadLine()
		if err == io.EOF {
			// Ignore errors here:
			_, _ = io.WriteString(s, "EOF.\n")
			break
		}
		if err != nil {
			// Ignore errors here:
			_, _ = io.WriteString(s, "Error while reading: "+err.Error())
			break
		}
		if line == "quit" {
			break
		}
		if line == "" {
			continue
		}
		output, err := handleTerminalInput(line)
		if err != nil {
			a.logger.Error("Error handling terminal input: %s", err)
			output = "Error handling terminal input: " + err.Error() + "\n"
		}
		io.WriteString(s, output)
	}
}

func handleTerminalInput(line string) (string, error) {
	ss := strings.SplitN(line, " ", 2)
	switch ss[0] {
	case "help":
		return "commands available: help, chonk <n>, echo <string>\n", nil
	case "chonk":
		if len(ss) < 2 {
			return "", fmt.Errorf("chonk requires a size argument")
		}
		chonkSize, _ := strconv.Atoi(ss[1])
		return handleChonker(chonkSize)
	case "echo":
		return fmt.Sprintf("%s\n", line), nil
	default:
		return fmt.Sprintf("no idea what you want\n"), nil
	}
}

func (a Server) checkPubKey(key ssh.PublicKey) bool {
	result := ssh.KeysEqual(key, a.pubKey)
	a.logger.Debugf("checkPubKey result: %v", result)
	return result
}

func (a Server) checkCert(cert ssh.PublicKey) bool {
	panic("confused")
}

func (a Server) myPubKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	a.logger.Debug("myPubKeyHandler")
	cert, ok := key.(*gossh.Certificate)
	if !ok {
		a.logger.Debug("myPubKeyHandler: not a cert")
		return a.checkPubKey(key)
	} else {
		a.logger.Debug("myPubKeyHandler: is a cert")
		return a.checkCert(cert)
	}
}

func handleChonker(size int) (string, error) {
	buf := make([]byte, size+1)
	for i := 0; i < size; i++ {
		buf[i] = 'a'
	}
	buf[size] = '\n'
	return string(buf), nil
}

func (a Server) userAuthorityChecker(signedWith gossh.PublicKey) bool {
	// Gets a binary rep of the pub part of our private key.
	a.logger.Debug("Checking user authority")
	caPubKey := a.pubKey.Marshal()
	if bytes.Equal(signedWith.Marshal(), caPubKey) {
		a.logger.Debug("User authority check passed")
		return true
	} else {
		a.logger.Debug("User authority check failed")
		return false
	}

}
