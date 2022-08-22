package sshmonitor

import (
	"context"
	"fmt"
	log "github.com/celerway/chainsaw"
	"github.com/gliderlabs/ssh"
	"github.com/perbu/sshpod/ctxio"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type endPoint struct {
	Host string
	Port int
}

func (endpoint *endPoint) String() string {
	return fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)
}

type monitor struct {
	logger *log.CircularLogger
	signer ssh.Signer
	ports  []int
}

// Connect sets up ssh monitor and starts an ssh connection.
func Connect(ctx context.Context, signer ssh.Signer, username, target string, logger *log.CircularLogger, ports ...int) {
	m := monitor{
		logger: logger,
		signer: signer,
		ports:  ports,
	}
	m.connect(ctx, target, username)
}

// connect sshs into a host (with the Signer) and registers two remote ports.
// when ctx is cancelled then the connection is shut down and the function returns.
// the function might also return if it encounters a serious error
func (m monitor) connect(ctx context.Context, target, username string) {

	sshConfig := &gossh.ClientConfig{
		User: username,
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(m.signer),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}
	// Connect to SSH remote server using serverEndpoint
	sshClient, err := gossh.Dial("tcp", target, sshConfig)
	if err != nil {
		m.logger.Errorf("Dial remote (%s) error: %s", target, err)
		time.Sleep(time.Second)
		return
	}
	m.logger.Infof("connected to %s, server %s", target, sshClient.ServerVersion())
	// We're connected. Let's start a shell session.
	sess, err := sshClient.NewSession()
	if err != nil {
		m.logger.Fatalf("Could not start ssh session: %s", err)
	} else {
		m.logger.Info("Session started....")
	}

	defer func(sess *gossh.Session) {
		err := sess.Close()
		if err != nil && err.Error() != "EOF" {
			m.logger.Errorf("Closing ssh session error: %s", err)
		}
	}(sess)

	modes := gossh.TerminalModes{
		gossh.ECHO:          0,     // disable echoing
		gossh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		gossh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	// Request pseudo terminal
	if err := sess.RequestPty("xterm", 80, 40, modes); err != nil {
		m.logger.Warnf("request for pseudo terminal failed: %s", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		m.logger.Fatalf("could not get the stdout pipe: %s", err)
	}
	err = sess.Shell()
	if err != nil {
		m.logger.Fatalf("Could not start ssh shell session: %s", err)
	}

	// spins off a goroutine to read the TTY coming from the server:
	go func(s io.Reader) {
		buf := make([]byte, 256)
		ctxReader := ctxio.NewReader(ctx, s) // Make a ctx-aware reader.
		for {
			n, err := ctxReader.Read(buf)
			if err != nil {
				if err.Error() != "EOF" {
					m.logger.Errorf("read error: %s", err)
				} else {
					m.logger.Tracef("expected read error: %s", err)
				}
				break
			}
			strOutput := strings.TrimSuffix(string(buf[:n]), "\r\n")
			m.logger.Debugf("server stdout: %s", strOutput)
			if strings.HasPrefix(strOutput, "HOSTNAME=") {
				hostname := strings.TrimPrefix(strOutput, "HOSTNAME=")
				m.logger.Infof("hostname: %s", hostname)
			}
		}
	}(stdout)

	wg := sync.WaitGroup{}
	wg.Add(1)
	childCtx, childCancel := context.WithCancel(ctx)
	childWg := sync.WaitGroup{}
	childWg.Add(len(m.ports))
	for _, port := range m.ports {
		go m.reverseListen(childCtx, &childWg, sshClient, port)
	}
	// Listen on remote server port
	m.logger.Debug("Reverse port forwarding setup. Waiting for teardown.")
	go func() {
		// wait for ctx to cancel.
		<-ctx.Done()
		err := sess.Close()
		if err != nil {
			m.logger.Errorf("Session close: %s", err)
		}
	}()
	go func() {
		err := sess.Wait()
		if err != nil && !strings.Contains(err.Error(), "remote command exited without exit status") {
			m.logger.Errorf("Session wait: %s", err)
		}
		childCancel()
		childWg.Wait()
		wg.Done()
	}()
	wg.Wait() // Wait for local wg to be done.
	err = sshClient.Close()
	if err != nil {
		m.logger.Errorf("Error closing ssh client for router: %s", err)
	}
}

func (m monitor) reverseListen(ctx context.Context, wg *sync.WaitGroup, client *gossh.Client, port int) {
	var endPoint = endPoint{
		Host: "localhost",
		Port: port,
	}
	m.logger.Debugf("Setting up reverse listen against %s", endPoint.String())
	listener, err := client.Listen("tcp", remoteEndpoint.String())
	if err != nil {
		m.logger.Errorf("Listen open port ON remote server error: %s", err)
		return
	}
	remotePort := getRemotePort(listener.Addr())
	m.logger.Infof("localhost:%d -> %s:%d", port, endPoint.Host, remotePort)
	m.logger.Debug("listen OK")
	done := false
	go func() { // Wait for the context to be cancelled, then set done to
		<-ctx.Done()
		m.logger.Debug("context cancelled")
		err := listener.Close()
		if err != nil {
			if err.Error() == "EOF" || strings.HasSuffix(err.Error(), "use of closed network connection") {
				m.logger.Tracef("Expected error closing listener: %s", err)
			} else {
				m.logger.Errorf("Error while closing listening ssh channel socket: '%s'", err)
			}
		}
		done = true
	}()
	for !done {
		m.logger.Debugf("Waiting for new conn in accept. Will forward to port %d", port)
		client, err := listener.Accept()
		if err != nil {
			if err.Error() != "EOF" {
				m.logger.Errorf("accepting connection error: %s", err)
			} else {
				m.logger.Tracef("accept error (expected): %s", err)
			}
			break // bail out of the goroutine
		}
		m.logger.Debug("connection accepted")
		// Open a (local) connection to localEndpoint whose content will be forwarded so serverEndpoint
		local, err := net.Dial("tcp", endPoint.String())
		if err != nil {
			m.logger.Errorf("dial local service: %s", err)
			_ = client.Close()
			time.Sleep(time.Second)
		} else {
			m.logger.Debugf("successfully dialed %s", endPoint.String())
			// Spin off a goroutine to handle to connection.
			go m.handleClient(ctx, client, local)
		}
	}
	m.logger.Debug("Shutting down reverse port")
	wg.Done()
}

func (m monitor) handleClient(ctx context.Context, client net.Conn, remote net.Conn) {

	defer func(c, r net.Conn) {
		err := c.Close()
		if err != nil {
			if err.Error() != "EOF" {
				m.logger.Errorf("closing client error: %s", err)
			}
		}
		err = r.Close()
		if err != nil {
			if err.Error() != "EOF" {
				m.logger.Errorf("closing remote error: %s", err)
			}
		}

	}(client, remote)

	chDone := make(chan bool)
	ctxClient := ctxio.NewReader(ctx, client)
	ctxRemote := ctxio.NewReader(ctx, remote)
	go func() { // Start remote -> local data transfer
		_, err := io.Copy(client, ctxRemote)
		if err != nil && !strings.HasSuffix(err.Error(), "use of closed network connection") {
			m.logger.Errorf("error while copy remote->local: %s", err)
		}
		chDone <- true
	}()

	go func() { // Start local -> remote data transfer
		_, err := io.Copy(remote, ctxClient)
		if err != nil && !strings.HasSuffix(err.Error(), "use of closed network connection") {
			m.logger.Errorf("error while copy local->remote: %s", err)
		}
		chDone <- true
	}()
	<-chDone
	m.logger.Tracef("Closing connection")
}

// remote forwarding port (on remote SSH server network)
var remoteEndpoint = endPoint{
	Host: "localhost",
	Port: 0,
}

func getRemotePort(a net.Addr) int {
	tcpAddr, ok := a.(*net.TCPAddr)
	if ok {
		return tcpAddr.Port
	} else {
		return 0
	}
}
