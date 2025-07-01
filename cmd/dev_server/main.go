package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crypto_rand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pinterest/knox"
	"github.com/pinterest/knox/log"
	"github.com/pinterest/knox/server"
	"github.com/pinterest/knox/server/auth"
	"github.com/pinterest/knox/server/keydb"
)

const caCert = `-----BEGIN CERTIFICATE-----
MIIB5jCCAYygAwIBAgIUD/1LTTQNvk3Rp9399flLlimbgngwCgYIKoZIzj0EAwIw
UTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRgwFgYDVQQKEw9NeSBDb21wYW55
IE5hbWUxGzAZBgNVBAMTEnVzZU9ubHlJbkRldk9yVGVzdDAeFw0xODAzMDIwMTU5
MDBaFw0yMzAzMDEwMTU5MDBaMFExCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEY
MBYGA1UEChMPTXkgQ29tcGFueSBOYW1lMRswGQYDVQQDExJ1c2VPbmx5SW5EZXZP
clRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARbSovOAo4ZimGBOn+tyftX
+GXShKsy2eFdvX9WfYx2NvYnw+RSM/JjRSBhUsCPXuEh/E5lhwRVfUxIlHry1CkS
o0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
jjNCAZxA5kjDK1ogrwkdziFiDgkwCgYIKoZIzj0EAwIDSAAwRQIgLXo9amyNn1Y3
qLpqrzVF7N7UQ3mxTl01MvnsqvahI08CIQCArwO8KmbPbN5XZrQ2h9zUgbsebwSG
dfOY505yMqiXig==
-----END CERTIFICATE-----`

var (
	flagAddr = flag.String("http", ":9000", "HTTP port to listen on")
)

const (
	authTimeout = 10 * time.Second
	serviceName = "knox_dev"
)

func main() {
	// Setup Knox logger
	logFile, err := os.OpenFile("knox_server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	accLogger := log.New(logFile, "", 0)
	errLogger := log.New(logFile, "", 0)
	accLogger.SetVersion("dev")
	accLogger.SetService(serviceName)
	errLogger.SetVersion("dev")
	errLogger.SetService(serviceName)

	flag.Parse()

	// Verify port is available
	if err := checkPortAvailable(*flagAddr); err != nil {
		fmt.Fprintf(logFile, "Port check failed: %v\n", err)
		os.Exit(1)
	}

	// Setup crypto and database
	dbEncryptionKey := []byte("testtesttesttest")
	cryptor := keydb.NewAESGCMCryptor(0, dbEncryptionKey)
	db := keydb.NewTempDB()

	// Add default access
	server.AddDefaultAccess(&knox.Access{
		Type:       knox.UserGroup,
		ID:         "security-team",
		AccessType: knox.Admin,
	})

	// Build TLS certificate
	tlsCert, tlsKey, err := buildCert()
	if err != nil {
		fmt.Fprintf(logFile, "Failed to build certificate: %v\n", err)
		os.Exit(1)
	}

	// Setup authentication
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM([]byte(caCert)) {
		fmt.Fprintln(logFile, "Failed to parse CA certificate")
		os.Exit(1)
	}

	decorators := []func(http.HandlerFunc) http.HandlerFunc{
		server.Logger(accLogger),
		server.AddHeader("Content-Type", "application/json"),
		server.AddHeader("X-Content-Type-Options", "nosniff"),
		server.Authentication(
			[]auth.Provider{
				auth.NewMTLSAuthProvider(certPool),
				auth.NewGitHubProvider(authTimeout),
				auth.NewSpiffeAuthProvider(certPool),
				auth.NewSpiffeAuthFallbackProvider(certPool),
			},
			nil),
	}

	// Get router
	r, err := server.GetRouter(cryptor, db, decorators, make([]server.Route, 0))
	if err != nil {
		fmt.Fprintf(logFile, "Failed to create router: %v\n", err)
		os.Exit(1)
	}

	http.Handle("/", r)

	// Start server
	fmt.Fprintf(logFile, "Starting server on %s\n", *flagAddr)
	if err := serveTLS(tlsCert, tlsKey, *flagAddr); err != nil {
		fmt.Fprintf(logFile, "Server failed: %v\n", err)
		os.Exit(1)
	}
}

func checkPortAvailable(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

func buildCert() ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crypto_rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year validity
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := crypto_rand.Int(crypto_rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Knox Dev"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(crypto_rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM, nil
}

func serveTLS(certPEMBlock, keyPEMBlock []byte, addr string) error {
	tlsConfig := &tls.Config{
		NextProtos:               []string{"http/1.1"},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		ClientAuth:               tls.RequestClientCert,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return err
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	server := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	fmt.Printf("Server listening on %s\n", addr)
	tlsListener := tls.NewListener(ln, tlsConfig)
	return server.Serve(tlsListener)
}
