// Copyright 2020 New Context, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vault

import (
	"crypto/sha1"
	"encoding/base64"
	"strings"

	"github.com/hashicorp/vault/api"
)

// IProxy defines the interface for the proxy to communicate with Vault PKI
type IProxy interface {
	CreateCertificate(name string, params Parameters) (map[string]interface{}, error)
	GetCertificate(name string) (Credential, error)
	PutCertificate(name string, cred Credential) error
	ListCertificates() ([]Credential, error)
	Login() error
	RevokeCertificate(name string) error
}

// Parameters contains values required to generate a certificate
type Parameters struct {
	KeyLength        int
	CommonName       string
	Organization     string
	OrganizationUnit string
	Locality         string
	State            string
	Country          string
	AlternativeNames []string
	ExtendedKeyUsage []string
	KeyUsage         []string
	Duration         int
	Ca               string
	SelfSign         bool
	IsCA             bool
}

// Credential is the generated certificate credential in Venafi's TPP
type Credential struct {
	Name        string   `json:"name"`
	Certificate string   `json:"certificate"`
	PrivateKey  string   `json:"private_key"`
	Chain       []string `json:"chain"`
	CommonName  string   `json:"common_name"`
	Serial      string   `json:"serial_number"`
	Role        string   `json:"role"`
}

// GetThumbprint calculates the fingerprint of a certificate in Vault
func GetThumbprint(cert string) ([sha1.Size]byte, error) {
	certStr := strings.ReplaceAll(cert, "-----BEGIN CERTIFICATE-----", "")
	certStr = strings.ReplaceAll(certStr, "-----END CERTIFICATE-----", "")
	certStr = strings.ReplaceAll(certStr, "\n", "")

	data, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		return [20]byte{}, err
	}

	return sha1.Sum(data), nil
}

// newClient creates a new vault client
func newClient(url string, token string) (*api.Client, error) {
	// Create a client with a nil configuration.
	// This will use Vault's default configuration and will try to parse configuration from
	// environment variables like "VAULT_ADDR" and "VAULT_TOKEN".
	client, err := api.NewClient(nil)
	if err != nil {
		return nil, err
	}

	// Override values if provided
	if url != "" {
		client.SetAddress(url)
	}

	if token != "" {
		client.SetToken(token)
	}

	return client, nil
}

// NewToken creates a new vault access token
func newToken(client *api.Client, cred map[string]string) (string, error) {
	if cred["token"] != "" {
		return cred["token"], nil
	}

	var url string
	var data map[string]interface{}

	switch cred["method"] {
	case "userpass":
		url = "/auth/userpass/login/" + cred["username"]
		data = map[string]interface{}{
			"password": cred["password"],
		}
	case "cert":
		url = "/auth/cert/login/"
		data = map[string]interface{}{
			"name": cred["certificate"],
		}
	}

	resp, err := client.Logical().Write(url, data)
	if err != nil {
		return "", err
	}

	token := resp.Auth.ClientToken

	return token, nil
}

// SecretEngine contains the config information for the Vault Secret Engine request proxy
type SecretEngine struct {
	Client      *api.Client
	AuthMethod  string
	BaseURL     string
	Token       string
	Username    string
	Password    string
	Path        string
	Certificate string
}

// Login generates an access token from a provided authentication method.
func (se *SecretEngine) Login() error {
	client, err := newClient(se.BaseURL, se.Token)
	if err != nil {
		return err
	}

	cred := map[string]string{
		"method":      se.AuthMethod,
		"token":       se.Token,
		"username":    se.Username,
		"password":    se.Password,
		"certificate": se.Certificate,
	}

	token, err := newToken(client, cred)
	if err != nil {
		return err
	}

	if token != "" {
		se.Token = token
		client.SetToken(se.Token)
	}

	se.Client = client

	return nil
}

// formats a path string for vault API operations
func formatDataPath(path, name, dataStr string) string {
	trimmedPath := strings.TrimLeft(path, "/")
	splitPath := strings.Split(trimmedPath, "/")

	dataPathSlice := []string{
		splitPath[0],
		dataStr,
	}

	dataPathSlice = append(dataPathSlice, splitPath[1:]...)
	dataPathSlice = append(dataPathSlice, name)

	dataPath := strings.Join(dataPathSlice, "/")
	dataPath = strings.TrimRight(dataPath, "/")

	return dataPath
}
