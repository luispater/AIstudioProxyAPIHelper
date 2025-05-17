package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

var (
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	certCache  = make(map[string]*tls.Certificate)
	cacheMutex sync.RWMutex
)

// Initialize CA certificate and key
func init() {
	// Read CA certificate
	caCertPEM, err := os.ReadFile("cert/ca.crt")
	if err != nil {
		panic(fmt.Sprintf("Cannot read CA certificate: %v", err))
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		panic("Cannot parse CA certificate PEM data")
	}
	caCert, err = x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		panic(fmt.Sprintf("Cannot parse CA certificate: %v", err))
	}

	// Read CA private key
	caKeyPEM, err := os.ReadFile("cert/ca.key")
	if err != nil {
		panic(fmt.Sprintf("Cannot read CA private key: %v", err))
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		panic("Cannot parse CA private key PEM data")
	}
	key, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		panic(fmt.Sprintf("Cannot parse CA private key: %v", err))
	}
	caKey = key.(*rsa.PrivateKey)
}

// GenerateCertificate generates a certificate for the specified domain
func GenerateCertificate(host string) (*tls.Certificate, error) {
	cacheMutex.RLock()
	if cert, ok := certCache[host]; ok {
		cacheMutex.RUnlock()
		return cert, nil
	}
	cacheMutex.RUnlock()

	// Generate new private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("Cannot generate private key: %v", err)
	}

	// Prepare certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("Cannot generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"MITM Proxy"},
			CommonName:   host,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add domain to SAN
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	// Sign with CA certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("Cannot create certificate: %v", err)
	}

	// Encode to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// Create TLS certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("Cannot create TLS certificate: %v", err)
	}

	// Cache certificate
	cacheMutex.Lock()
	certCache[host] = &tlsCert
	cacheMutex.Unlock()

	return &tlsCert, nil
}
