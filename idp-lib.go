package main

// to convert .12 files to .cer + .key file combination
// $ openssl pkcs12 -in client-id.p12 -clcerts -nokeys -out client-id.cer
// $ openssl pkcs12 -in client-id.p12 -clcerts -nodes -nocerts | openssl rsa > client-id.key

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"math/big"
	"time"
	"io/ioutil"
	"bytes"
	"errors"
	"net/http"
)

type Client_Validation_Ticket struct {
	cache       *Identity_Profile
	added       time.Time
	serial_no   big.Int
	device_name string
	device_type string
}

var validation_tickets = make(map[string]Client_Validation_Ticket)

func validate_client_certificate(client_cert *x509.Certificate) (*Identity_Profile, string) {

	var cached_validation Client_Validation_Ticket

	// if no elementary errors have been found

	cached_validation = validation_tickets[client_cert.SerialNumber.String()]
	error_reason := ""

	// if we have a cache that is not older than 5 minutes, we skip
	if cached_validation.cache == nil || time.Now().Sub(cached_validation.added).Seconds() > 60 {
		log.Printf("re-validating mTLS ID: %f\n", time.Now().Sub(cached_validation.added).Seconds())
		ans := identity_inquiry(client_cert.SerialNumber.String())
		// "476701752658536845")

		if ans.IdentityProfile.Outcome != "" {

			// in case we receive a profile
			// for this, the certificate needs to be valid, not timed out or reported
			if ans.IdentityProfile.Outcome[0:2] == "OK" {

				// the user has a role in the server
				// let's cache this result for a few minutes
				// if a cache exists, we will overwrite it
				cached_validation = Client_Validation_Ticket{
					cache:       &ans.IdentityProfile,
					added:       time.Now(),
					serial_no:   *client_cert.SerialNumber,
					device_name: client_cert.Subject.CommonName,
					device_type: client_cert.Subject.OrganizationalUnit[0],
				}

				validation_tickets[client_cert.SerialNumber.String()] = cached_validation

			} else {
				error_reason = ans.SimpleResponse.Outcome
			}

		} else {
			error_reason = ans.SimpleResponse.Outcome
		}
	}

	// we will look a the roles now, and if there are no roles defined
	// the client clearly has no business here
	if error_reason == "" && len(cached_validation.cache.ServiceRoles) == 0 {
		error_reason = "Certificate is valid no roles on this service"
	}

	// means it allows the user to continue execution through he proxy
	return cached_validation.cache, error_reason
}

func identity_inquiry(serial_no string) IDP_Response {

	ans := do_get("{\"Identity-Inquiry\":{\"serial-number\": \"" + serial_no + "\"}}")
	return ans

}

//
// just a set of wrappers around the methods
//
func do_get(request_body string) IDP_Response {
	return do_call("GET", request_body)
}

func do_put(request_body string) IDP_Response {
	return do_call("PUT", request_body)
}

func do_post(request_body string) IDP_Response {
	return do_call("POST", request_body)
}

func do_delete(request_body string) IDP_Response {
	return do_call("DELETE", request_body)
}

//
// returns 2 values int this order: the http response status (int) and the body of the answer ([]byte)
// - if the http response code is anything but 200, the body should be expected to contain
//   some error description
// - an error of 600 as response code means the call could not be made due to whatever reason
// - 5xx errors mean the request was made, but generated a server error
//
func do_call(method string, request_body string) IDP_Response {
	// log.Printf("making https call: %s\n", request_body)

	client, err := client()

	if err != nil {
		oc := Simple_Response{Outcome: ("Unable to create http client: " + err.Error())}
		log.Printf("error creating client: %s\n", err.Error())
		return IDP_Response{http_code: 600, SimpleResponse: oc}
	}

	// var body_reader io.Reader
	var jsonStr = []byte(request_body)
	client_request, err := http.NewRequest(method, "https://api.identity.plus/v1", bytes.NewBuffer(jsonStr))
	client_request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(client_request)

	defer func() {
		// only close body if it exists to prevent nil reference
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()

	if err != nil {
		oc := Simple_Response{Outcome: ("error during https call: " + err.Error())}
		log.Printf("error during https call: %s\n", err.Error())
		return IDP_Response{http_code: 600, SimpleResponse: oc}
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		oc := Simple_Response{Outcome: ("error decoding https answer: " + err.Error())}
		log.Printf("error decoding https answer: %s\n", err.Error())
		return IDP_Response{http_code: 600, SimpleResponse: oc}
	}

	// log.Printf("Identity Broker response: %s\n", string(bodyBytes))

	var response IDP_Response

	json.Unmarshal(bodyBytes, &response)
	response.http_code = resp.StatusCode

	return response
}

//
// Lazily creates a http client and caches it so that next time it does not have to create it
// also, this leverages re-use of TCP/TLS connection such that we do not have to do tripple
// handshake at every call: 7ZR8XFK36HZEYHDVTTZU
//
var __client *http.Client

func client() (*http.Client,  error) {

	// create the client if not yet created
	if __client == nil {

		if __config.IdentityFolder == "" || __config.AgentName == "" {
			return nil, errors.New("client certificate or key not properly specified. They need to be in separate files as DER Encoded")
		}

		clientCert, err := tls.LoadX509KeyPair(__config.IdentityFolder + "/" + __config.AgentName + ".cer", __config.IdentityFolder + "/" + __config.AgentName + ".key")

		if err != nil {
			return nil, errors.New("error loading key material: " + err.Error())
		}

		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{clientCert},
		}

		transport := http.Transport{
			TLSClientConfig: &tlsConfig,
		}

		__client = &http.Client{
			Transport: &transport,
			Timeout:   time.Second * 5,
		}
	}

	return __client, nil
}

//
// Type mapping definitions for ReST communiation
// We are going to create a big structure to aid automatic identification of types
//

type IDP_Response struct {
	SimpleResponse  Simple_Response  `json:"Simple-Response"`
	IdentityProfile Identity_Profile `json:"Identity-Profile"`
	http_code       int
}

type Simple_Response struct {
	Outcome string `json:"outcome"`
}

type Identity_Profile struct {
	OrgID              string   `json:"organizational-reference"`
	LocalUserID        string   `json:"local-user-id"`
	ServiceRoles       []string `json:"service-roles"`
	TrustSponsors      []string `json:"trust-sponsors"`
	SitesFrequented    int      `json:"sites-frequented"`
	AverageIdentityAge int      `json:"average-identity-age"`
	MaxIdentityAge     int      `json:"max-identity-age"`
	TrustScore         int      `json:"trust-score"`
	LocalTrust         int      `json:"local-trust"`
	LocalIntrusions    int      `json:"local-intrusions"`
	Outcome            string   `json:"outcome"`
}

