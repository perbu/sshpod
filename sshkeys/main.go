package sshkeys

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"os"
)

// GetPrivateKey reads a private key from a file and returns a ssh.Signer
func GetPrivateKey(fh io.Reader) (ssh.Signer, error) {
	pemBytes, err := ioutil.ReadAll(fh)
	if err != nil {
		return nil, fmt.Errorf("could not read private key: %w", err)
	}
	if len(pemBytes) == 0 {
		return nil, errors.New("empty private key")
	}
	privKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("could not create signer from private key: %w", err)
	}
	return signer, nil
}

func GetPrivateKeyFile(name string) (ssh.Signer, error) {
	fh, err := os.Open(name)
	defer fh.Close()
	if err != nil {
		return nil, fmt.Errorf("could not open private key file (%s): %w", name, err)
	}
	return GetPrivateKey(fh)
}

// GetPublicKey return the public key or CA (they are the same) from a file handle
func GetPublicKey(fh io.Reader) (ssh.PublicKey, error) {
	caBytes, err := ioutil.ReadAll(fh)
	if err != nil {
		return nil, fmt.Errorf("could not read ca: %w", err)
	}
	ca, _, _, _, err := ssh.ParseAuthorizedKey(caBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse c: %w", err)
	}
	return ca, nil
}

func GetPublicKeyFile(name string) (ssh.PublicKey, error) {
	fh, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("could not open public key file (%s): %w", name, err)
	}
	defer fh.Close()
	return GetPublicKey(fh)
}

// GetPrivateCert reads a private key from the keyfh, then reads the
// cert from the  certfh
// It returns an ssh.Signer or error
func GetPrivateCert(keyfh, certfh io.Reader) (ssh.Signer, error) {
	signer, err := GetPrivateKey(keyfh)
	if err != nil {
		return nil, fmt.Errorf("could not get private key via GetPrivateKey: %w", err)
	}
	cert, err := unmarshalCert(certfh)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling cert: %w", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, fmt.Errorf("could not create cert signer: %w", err)
	}
	return certSigner, nil
}

func GetPrivateCertFile(keyName, certName string) (ssh.Signer, error) {
	keyFh, err := os.Open(keyName)
	if err != nil {
		return nil, fmt.Errorf("could not open private key file (%s): %w", keyName, err)
	}
	defer keyFh.Close()
	certFh, err := os.Open(certName)
	if err != nil {
		return nil, fmt.Errorf("could not open cert file (%s): %w", certName, err)
	}
	defer certFh.Close()
	return GetPrivateCert(keyFh, certFh)
}

// unmarshalCert unmarshal a cert from a file handle
// It is implicitly tested by the test for GetPrivateCert
func unmarshalCert(fh io.Reader) (*ssh.Certificate, error) {
	certBytes, err := ioutil.ReadAll(fh)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("failed to cast to certificate, type is %T", pub)
	}
	return cert, nil
}
