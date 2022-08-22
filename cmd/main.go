package main

import (
	"context"
	"fmt"
	log "github.com/celerway/chainsaw"
	"github.com/joho/godotenv"
	"github.com/perbu/sshpod/httpd"
	"github.com/perbu/sshpod/sshd"
	"github.com/perbu/sshpod/sshkeys"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"sync"
)

func main() {
	err := realMain()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Exiting...")
}

func realMain() error {
	logger := log.MakeLogger("main")
	logger.SetLevel(log.TraceLevel)
	err := godotenv.Load()
	if err != nil {
		logger.Errorf("Error loading .env file: ", err)
	}
	httpUser := getEnvString("HTTP_USER", "", true)
	httpPass := getEnvString("HTTP_PASS", "", true)
	httpPort := getEnvInt("HTTP_PORT", 0, false)
	routerId := getEnvInt("ROUTER_ID", rand.Intn(1000)+1, false)
	privKeyPath := getEnvString("PRIV_KEY_PATH", "", true)
	privCertPath := getEnvString("PRIV_CERT_PATH", "", true)
	pubKeyPath := getEnvString("PUB_KEY_PATH", "", true)
	sshPort := getEnvInt("SSHD_PORT", 0, false)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	wg := sync.WaitGroup{}

	httpLogger := log.MakeLogger("httpd")
	httpLogger.SetLevel(log.TraceLevel)
	httpServer, err := httpd.New(httpLogger, routerId, httpPort, httpUser, httpPass)
	if err != nil {
		return err
	}

	// Start the httpd server
	wg.Add(1)
	go func() {
		defer wg.Done()

		httpServer.Run(ctx)
		if err != nil {
			log.Fatal(err)
		}
	}()

	// Start the sshd server:
	signer, err := sshkeys.GetPrivateCertFile(privKeyPath, privCertPath)
	if err != nil {
		return fmt.Errorf("error loading private key: %s", err)
	}
	pubKey, err := sshkeys.GetPublicKeyFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("error loading public key: %s", err)
	}
	sshdLogger := log.MakeLogger("sshd")
	sshdLogger.SetLevel(log.TraceLevel)
	sshServer, err := sshd.New(signer, pubKey, routerId, sshPort, sshdLogger)
	if err != nil {
		return fmt.Errorf("error creating ssh server: %s", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		sshServer.Run(ctx)
	}()

	// monitorSigner :=
	// Set up the SSH monitor
	// sshMonitor := sshmonitor.Connect(ctx, )

	logger.Info("Services up and running. Waiting for interrupt...")
	wg.Wait()
	logger.Info("Services stopped.")
	return nil
}

func getEnvString(key, defaultValue string, required bool) string {
	value := os.Getenv(key)
	if value == "" && required {
		log.Fatalf("%s environment variable is required", key)
	}
	if value == "" {
		return defaultValue
	}
	return value
}

func getEnvInt(key string, defaultValue int, required bool) int {
	value := os.Getenv(key)
	if value == "" && required {
		log.Fatalf("%s environment variable is required", key)
	}
	if value == "" {
		return defaultValue
	}
	i, err := strconv.Atoi(value)
	if err != nil {
		log.Fatalf("%s environment variable is not an integer: %s", key, err)
	}
	return i
}
