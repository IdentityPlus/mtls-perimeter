package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"golang.org/x/net/http2"
	"github.com/gorilla/websocket"
)

type Config struct {
	Protocol        string   `json:"protocol"`
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
	Verbose		    bool	 `json:"verbose"`
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

	if __config.Verbose {
		log.Printf("Authenticating traffic between (remote: %s) -- mTLS --> (inbound: %s/TCP) -- TCP --> %s (outbound: %s/mTLS)", client_conn.RemoteAddr(), config.FrontendAddress, config.BackendAddress)
	}

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

func load_tls_config(config *Config, authenticate_client func(*x509.Certificate) bool) (*tls.Config, error) {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(config.ServerCert, config.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert and key: %v", err)
	}

	// Load CA certificate to verify client certs
	ca_cert, err := ioutil.ReadFile(config.CACert)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %v", err)
	}

	ca_pool := x509.NewCertPool()
	if !ca_pool.AppendCertsFromPEM(ca_cert) {
		return nil, fmt.Errorf("failed to append CA certs")
	}

	// Set up mTLS configuration
	tls_config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    ca_pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: func(raw_certs [][]byte, verified_chains [][]*x509.Certificate) error {
			client_cert := verified_chains[0][0]
			if !authenticate_client(client_cert) {
				return fmt.Errorf("client certificate rejected")
			}
			return nil
		},
	}

	return tls_config, nil
}
	
func start_tls_server(config *Config) error {
	// Load server certificate and key
	// and configure TLS with Client certificate authentication call back 
	tls_config, err := load_tls_config(config, authenticate_client)

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

func start_tls_http_server(config *Config) error {
	tls_config, err := load_tls_config(config, authenticate_client)
	if err != nil {
		return fmt.Errorf("failed to load TLS config: %v", err)
	}

	// Use HTTP/2
	tls_config.NextProtos = []string{"h2", "http/1.1"}

	// Create the HTTP server
	server := &http.Server{
		Addr:      config.FrontendAddress,
		TLSConfig: tls_config,
	}

	// HTTP/2 support
	http2.ConfigureServer(server, &http2.Server{})

	// Backend URL (plain HTTP connection)
	backend_url, err := url.Parse(config.BackendAddress)
	if err != nil {
		return fmt.Errorf("failed to parse backend address: %v", err)
	}

	// Reverse proxy to backend
	proxy := httputil.NewSingleHostReverseProxy(backend_url)

	// WebSocket upgrader
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	// Handle incoming HTTP and WebSocket requests
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// WebSocket upgrade check
		if websocket.IsWebSocketUpgrade(r) {
			handle_websocket_connection(w, r, backend_url, upgrader)
			return
		}

		// Forward HTTP/1.1 and HTTP/2 traffic to backend
		proxy.ServeHTTP(w, r)
	})

	log.Printf("Starting server on %s (TLS)", config.FrontendAddress)
	return server.ListenAndServeTLS("", "")
}

func handle_websocket_connection(w http.ResponseWriter, r *http.Request, backendURL *url.URL, upgrader websocket.Upgrader) {
	// Upgrade inbound HTTP request to a WebSocket connection
	inboundWS, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade to WebSocket: %v", err)
		return
	}
	defer inboundWS.Close()

	// Dial the backend WebSocket server
	backendWS, _, err := websocket.DefaultDialer.Dial(backendURL.String(), nil)
	if err != nil {
		log.Printf("Failed to connect to backend WebSocket: %v", err)
		return
	}
	defer backendWS.Close()

	// Forward traffic between inbound and backend WebSocket
	done := make(chan struct{})
	go func() {
		io_copy_ws(inboundWS, backendWS)
		done <- struct{}{}
	}()
	go func() {
		io_copy_ws(backendWS, inboundWS)
		done <- struct{}{}
	}()

	<-done
	<-done
}

func io_copy_ws(src *websocket.Conn, dst *websocket.Conn) {
	for {
		messageType, message, err := src.ReadMessage()
		if err != nil {
			log.Printf("Error reading WebSocket message: %v", err)
			break
		}
		if err := dst.WriteMessage(messageType, message); err != nil {
			log.Printf("Error writing WebSocket message: %v", err)
			break
		}
	}
}

var __config *Config

func main() {
	args := os.Args[1:]
	var config_file = "config.json"

	if len(args) > 0 {
		config_file = args[0]
	}

	config, err := load_config(config_file)
	
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	__config = config

	if __config.Protocol == "HTTP" { 
		if err := start_tls_server(__config); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	} else {
		if err := start_tls_server(__config); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}
}
