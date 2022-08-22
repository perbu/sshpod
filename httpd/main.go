package httpd

import (
	"context"
	"encoding/base64"
	"fmt"
	log "github.com/celerway/chainsaw"
	"github.com/gorilla/mux"
	"net"
	"net/http"
	"strings"
	"time"
)

const useAuth = false

type Server struct {
	routerId int
	user     string
	pass     string
	logger   log.Logger
	port     int
	router   *mux.Router
	listener net.Listener
}

func New(logger log.Logger, routerId int, port int, user, pass string) (Server, error) {
	server := Server{
		routerId: routerId,
		user:     user,
		pass:     pass,
		logger:   logger,
	}
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		server.logger.Fatalf("net.Listen: ", err)
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port
	server.port = actualPort
	router := mux.NewRouter()
	if useAuth {
		router.HandleFunc("/", use(server.myHandler, server.basicAuth))
	} else {
		router.HandleFunc("/", server.myHandler)
	}
	router.HandleFunc("/stream", server.streamHandler) // no auth.

	server.router = router
	server.listener = listener
	return server, nil
}

func (s Server) Port() int {
	return s.port
}

func (s Server) Run(ctx context.Context) {
	s.logger.Infof("Webserver for ID %d on: :%d", s.routerId, s.port)

	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()
	err := http.Serve(s.listener, s.router)
	if err != nil {
		if ctx.Err() == nil {
			log.Fatal("http.Serve: ", err)
		}
		s.logger.Info("shutting down httpd: ", err)
	}
}

func use(h http.HandlerFunc, middleware ...func(http.HandlerFunc) http.HandlerFunc) http.HandlerFunc {
	for _, m := range middleware {
		h = m(h)
	}
	return h
}

func (s Server) myHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(fmt.Sprintf("This is the router HTTP interface for router %d", s.routerId)))
	if err != nil {
		log.Fatal(err)
	}
	s.logger.Info("RouterId: %d Web access to %s", s.routerId, r.RequestURI)
	return
}

func (s Server) streamHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-type", "text/event-stream")
	flusher, ok := w.(http.Flusher)
	if !ok {
		panic("expected http.ResponseWriter to be an http.Flusher")
	}
	w.WriteHeader(http.StatusOK)
	for i := 0; i < 100; i++ {
		_, err := w.Write([]byte(fmt.Sprintf("%d\n", i)))
		if err != nil {
			s.logger.Info("write error: ", err)
			break
		}
		flusher.Flush()
		time.Sleep(100 * time.Millisecond)
	}
	return
}

// Leverages nemo's answer in http://stackoverflow.com/a/21937924/556573
func (s Server) basicAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(auth) != 2 {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
		b, err := base64.StdEncoding.DecodeString(auth[1])
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		pair := strings.SplitN(string(b), ":", 2)
		if len(pair) != 2 {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
		if pair[0] != s.user || pair[1] != s.pass {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}
}
