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
	"io"
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
	flagHTTPPort  = flag.String("http", ":8080", "HTTP port for redirects")
	flagHTTPSPort = flag.String("https", ":9000", "HTTPS port to listen on")
)

const (
	authTimeout = 10 * time.Second
	serviceName = "knox_dev"
)

func main() {
	// Setup dual logging
	logFile, err := os.OpenFile("knox_server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()
	writer := io.MultiWriter(os.Stdout, logFile)

	flag.Parse()

	// Verify ports are available
	if err := checkPortAvailable(*flagHTTPPort); err != nil {
		fmt.Fprintf(writer, "HTTP port check failed: %v\n", err)
		os.Exit(1)
	}
	if err := checkPortAvailable(*flagHTTPSPort); err != nil {
		fmt.Fprintf(writer, "HTTPS port check failed: %v\n", err)
		os.Exit(1)
	}

	// Generate TLS certificate
	tlsCert, tlsKey, err := generateTLSCertificate()
	if err != nil {
		fmt.Fprintf(writer, "Failed to generate TLS certificate: %v\n", err)
		os.Exit(1)
	}

	// Setup database and cryptor
	dbEncryptionKey := []byte("testtesttesttest")
	cryptor := keydb.NewAESGCMCryptor(0, dbEncryptionKey)
	db := keydb.NewTempDB()

	// Configure default access
	server.AddDefaultAccess(&knox.Access{
		Type:       knox.UserGroup,
		ID:         "security-team",
		AccessType: knox.Admin,
	})

	// Setup authentication
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM([]byte(caCert)) {
		fmt.Fprintf(writer, "Failed to parse CA certificate\n")
		os.Exit(1)
	}

	// Initialize Knox logger
	knoxLogger := log.New(writer, "", 0)
	knoxLogger.SetVersion("dev")
	knoxLogger.SetService(serviceName)

	// Configure authentication providers
	authProviders := []auth.Provider{
		// GitHub provider for testing (you'll need to configure this properly)
		auth.NewGitHubProvider(authTimeout),
		
		// mTLS provider for production
		auth.NewMTLSAuthProvider(certPool),
		
		// SPIFFE providers for service identity
		auth.NewSpiffeAuthProvider(certPool),
		auth.NewSpiffeAuthFallbackProvider(certPool),
	}

	// Configure server decorators
	decorators := []func(http.HandlerFunc) http.HandlerFunc{
		server.Logger(knoxLogger),
		server.AddHeader("Content-Type", "application/json"),
		server.AddHeader("X-Content-Type-Options", "nosniff"),
		server.Authentication(authProviders, nil),
	}

	// Create router
	r, err := server.GetRouter(cryptor, db, decorators, make([]server.Route, 0))
	if err != nil {
		fmt.Fprintf(writer, "Failed to create router: %v\n", err)
		os.Exit(1)
	}
	http.Handle("/", r)

	// Start HTTP redirect server
	go func() {
		fmt.Fprintf(writer, "Starting HTTP redirect server on %s\n", *flagHTTPPort)
		if err := http.ListenAndServe(*flagHTTPPort, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+*flagHTTPSPort+r.RequestURI, http.StatusMovedPermanently)
		})); err != nil {
			fmt.Fprintf(writer, "HTTP server failed: %v\n", err)
			os.Exit(1)
		}
	}()

	// Start HTTPS server
	fmt.Fprintf(writer, "Starting HTTPS server on %s\n", *flagHTTPSPort)
	if err := startHTTPSServer(tlsCert, tlsKey, *flagHTTPSPort, writer); err != nil {
		fmt.Fprintf(writer, "HTTPS server failed: %v\n", err)
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

func generateTLSCertificate() ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), crypto_rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := crypto_rand.Int(crypto_rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
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

	certDER, err := x509.CreateCertificate(crypto_rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})

	return certPEM, keyPEM, nil
}

func startHTTPSServer(certPEM, keyPEM []byte, addr string, writer io.Writer) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
	}

	tlsListener := tls.NewListener(ln, tlsConfig)
	return server.Serve(tlsListener)
}
