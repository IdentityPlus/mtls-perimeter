package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
)

type Config struct {
	FrontendAddress string   `json:"frontend_address"`
	ServerCert      string   `json:"server_cert"`
	ServerKey       string   `json:"server_key"`
	RolesAllowed    []string `json:"roles_allowed"`

	IdentityBroker  string   `json:"identity_broker"`
	CACert          string   `json:"identity_broker_ca"`
	IdentityFolder  string   `json:"mtls_id_directory"`
	AgentName       string   `json:"mtls_id"`
	MTLSID_TTL	    int      `json:"mtls_id_ttl"`

	BackendAddress  string   `json:"backend_address"`
}

func load_config(file string) (*Config, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func authenticate_client(cert *x509.Certificate) bool {
	// For now, just print certificate info. In a real scenario, add logic to verify the client certificate.
	identity_profile, error_cause := validate_client_certificate(cert)

	if error_cause != "" {
		log.Printf("Access denied to mTLS ID: {SN: %s, Agent: \"%s\"} on account of: %s\n", cert.SerialNumber.String(), cert.Subject.CommonName, error_cause)
		return false
	}

	var roles = ""
	var allowed = false

	for _, role := range identity_profile.ServiceRoles {
		
		if len(roles) > 0 {
			roles = roles + ", "
		}
		roles = roles + "\"" + role + "\""
		
		for _, allowed_role := range __config.RolesAllowed {
			if !allowed && role == allowed_role {
				allowed = true
			}
		}
	}

	if allowed {
		
		log.Printf("Access granted to mTLS ID: {SN: %s, Agent: \"%s\", Org-ID: \"%s\", Roles: [%s]}\n", cert.SerialNumber.String(), cert.Subject.CommonName, identity_profile.OrgID, roles)
		return true

	} else {

		log.Printf("Access denied to mTLS ID: {SN: %s, Agent: \"%s\", Org-ID: \"%s\", Roles: [%s]}\n", cert.SerialNumber.String(), cert.Subject.CommonName, identity_profile.OrgID, roles)
		return false

	}


	return true // Placeholder: Return true if valid, false if not
}

func handle_connection(client_conn net.Conn, config *Config) {
	defer client_conn.Close()

	// Connect to the backend
	backend_conn, err := net.Dial("tcp", config.BackendAddress)
	if err != nil {
		log.Printf("Failed to connect to backend: %v", err)
		return
	}
	defer backend_conn.Close()

	log.Printf("Authenticating traffic between (remote: %s) -- mTLS --> (inbound: %s/TCP) -- TCP --> %s (outbound: %s/mTLS)", client_conn.RemoteAddr(), config.FrontendAddress, config.BackendAddress)

	done := make(chan struct{})
	
	// Forward traffic in both directions
	go func() {
		_, _ = io.Copy(backend_conn, client_conn)
		client_conn.Close()
		backend_conn.Close()
		done <- struct{}{}
	}()

	go func() {
		_, _ = io.Copy(client_conn, backend_conn)
		client_conn.Close()
		backend_conn.Close()
		done <- struct{}{}
	}()

	// Wait for both sides to finish
	<-done
	<-done
}

func start_tls_server(config *Config) error {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(config.ServerCert, config.ServerKey)
	if err != nil {
		return fmt.Errorf("failed to load server cert and key: %v", err)
	}

	// Load CA certificate to verify client certs
	ca_cert, err := ioutil.ReadFile(config.CACert)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %v", err)
	}

	ca_pool := x509.NewCertPool()
	if !ca_pool.AppendCertsFromPEM(ca_cert) {
		return fmt.Errorf("failed to append CA certs")
	}

	// Configure mutual TLS
	tls_config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    ca_pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: func(raw_certs [][]byte, verified_chains [][]*x509.Certificate) error {
			// Extract client certificate
			client_cert := verified_chains[0][0]
			if !authenticate_client(client_cert) {
				return fmt.Errorf("client certificate rejected")
			}
			return nil
		},
	}

	listener, err := tls.Listen("tcp", config.FrontendAddress, tls_config)
	if err != nil {
		return fmt.Errorf("failed to start TLS listener: %v", err)
	}
	defer listener.Close()

	log.Printf("Listening on %s (TLS)", config.FrontendAddress)

	for {
		client_conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handle_connection(client_conn, config)
	}
}

var __config *Config

func main() {
	config, err := load_config("config.json")
	
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	__config = config
	if err := start_tls_server(__config); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
