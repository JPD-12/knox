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
<<<<<<< HEAD
=======
	"io"
>>>>>>> 1f2823a (Fix formatting: remove trailing blank line)
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
<<<<<<< HEAD
	// Setup Knox logger
=======
	// Setup dual logging
>>>>>>> 1f2823a (Fix formatting: remove trailing blank line)
	logFile, err := os.OpenFile("knox_server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()
<<<<<<< HEAD

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
=======
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
>>>>>>> 1f2823a (Fix formatting: remove trailing blank line)
	dbEncryptionKey := []byte("testtesttesttest")
	cryptor := keydb.NewAESGCMCryptor(0, dbEncryptionKey)
	db := keydb.NewTempDB()

<<<<<<< HEAD
	// Add default access
=======
	// Configure default access
>>>>>>> 1f2823a (Fix formatting: remove trailing blank line)
	server.AddDefaultAccess(&knox.Access{
		Type:       knox.UserGroup,
		ID:         "security-team",
		AccessType: knox.Admin,
	})

<<<<<<< HEAD
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
=======
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
>>>>>>> 1f2823a (Fix formatting: remove trailing blank line)
		server.AddHeader("Content-Type", "application/json"),
		server.AddHeader("X-Content-Type-Options", "nosniff"),
		server.Authentication(authProviders, nil),
	}

<<<<<<< HEAD
	// Get router
	r, err := server.GetRouter(cryptor, db, decorators, make([]server.Route, 0))
	if err != nil {
		fmt.Fprintf(logFile, "Failed to create router: %v\n", err)
=======
	// Create router
	r, err := server.GetRouter(cryptor, db, decorators, make([]server.Route, 0))
	if err != nil {
		fmt.Fprintf(writer, "Failed to create router: %v\n", err)
>>>>>>> 1f2823a (Fix formatting: remove trailing blank line)
		os.Exit(1)
	}
	http.Handle("/", r)

<<<<<<< HEAD
	// Start server
	fmt.Fprintf(logFile, "Starting server on %s\n", *flagAddr)
	if err := serveTLS(tlsCert, tlsKey, *flagAddr); err != nil {
		fmt.Fprintf(logFile, "Server failed: %v\n", err)
=======
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
>>>>>>> 1f2823a (Fix formatting: remove trailing blank line)
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

<<<<<<< HEAD
func buildCert() ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crypto_rand.Reader)
=======
func generateTLSCertificate() ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), crypto_rand.Reader)
>>>>>>> 1f2823a (Fix formatting: remove trailing blank line)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
<<<<<<< HEAD
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year validity
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := crypto_rand.Int(crypto_rand.Reader, serialNumberLimit)
=======
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := crypto_rand.Int(crypto_rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
>>>>>>> 1f2823a (Fix formatting: remove trailing blank line)
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

<<<<<<< HEAD
	derBytes, err := x509.CreateCertificate(crypto_rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
=======
	certDER, err := x509.CreateCertificate(crypto_rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
>>>>>>> 1f2823a (Fix formatting: remove trailing blank line)
	if err != nil {
		return nil, nil, err
	}

<<<<<<< HEAD
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
=======
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})
>>>>>>> 1f2823a (Fix formatting: remove trailing blank line)

	return certPEM, keyPEM, nil
}

<<<<<<< HEAD
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
=======
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
>>>>>>> 1f2823a (Fix formatting: remove trailing blank line)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

<<<<<<< HEAD
	fmt.Printf("Server listening on %s\n", addr)
	tlsListener := tls.NewListener(ln, tlsConfig)
	return server.Serve(tlsListener)
}
=======
	server := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
	}

	tlsListener := tls.NewListener(ln, tlsConfig)
	return server.Serve(tlsListener)
}
>>>>>>> 1f2823a (Fix formatting: remove trailing blank line)
