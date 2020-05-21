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

package vcert

import (
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/newcontext/vault-venafi/output"
)

var origin = "NewContext Vault-Venafi"

// IProxy defines the interface for proxies that manage requests to vcert
type IProxy interface {
	GenerateCertificate(args *CertArgs) (*certificate.PEMCollection, error)
	RetrieveCertificateByThumbprint(thumprint string) (*certificate.PEMCollection, error)
	RevokeCertificate(thumbprint string) error
	PutCertificate(certName string, cert string, privateKey string) error
	ListCertificates(vlimit int, zone string) ([]certificate.CertificateInfo, error)
	Login() error
}

// Proxy contains the necessary config information for a vcert proxy
type Proxy struct {
	Username      string
	Password      string
	Zone          string
	BaseURL       string
	ConnectorType string
	Client        endpoint.Connector
}

// PutCertificate uploads a certificate to vcert
func (p *Proxy) PutCertificate(certName string, cert string, privateKey string) error {
	importReq := &certificate.ImportRequest{
		// if PolicyDN is empty, it is taken from cfg.Zone
		ObjectName:      certName,
		CertificateData: cert,
		PrivateKeyData:  privateKey,
		// Password:        "newPassw0rd!",
		Reconcile: false,
		CustomFields: []certificate.CustomField{
			{
				Type:  certificate.CustomFieldOrigin,
				Name:  "Origin",
				Value: origin,
			},
		},
	}

	importResp, err := p.Client.ImportCertificate(importReq)
	if err != nil {
		return err
	}

	output.Verbose("%+v", importResp)

	return nil
}

// ListCertificates retrieves the list of certificates from vcert
func (p *Proxy) ListCertificates(limit int, zone string) ([]certificate.CertificateInfo, error) {
	output.Info("vcert list from proxy")

	p.Client.SetZone(prependVEDRoot(zone))

	filter := endpoint.Filter{Limit: &limit, WithExpired: true}

	certInfo, err := p.Client.ListCertificates(filter)
	if err != nil {
		return []certificate.CertificateInfo{}, err
	}

	output.Verbose("certInfo %+v", certInfo)

	for a, b := range certInfo {
		output.Verbose("cert %+v %+v\n", a, b)
	}

	return certInfo, nil
}

// RetrieveCertificateByThumbprint fetches a certificate from vcert by the thumbprint
func (p *Proxy) RetrieveCertificateByThumbprint(thumprint string) (*certificate.PEMCollection, error) {
	pickupReq := &certificate.Request{
		Thumbprint: thumprint,
		Timeout:    180 * time.Second,
	}

	return p.Client.RetrieveCertificate(pickupReq)
}

// Login creates a session with the TPP server
func (p *Proxy) Login() error {
	auth := endpoint.Authentication{
		User:     p.Username,
		Password: p.Password,
	}

	var connectorType endpoint.ConnectorType

	switch p.ConnectorType {
	case "tpp":
		connectorType = endpoint.ConnectorTypeTPP
	default:
		return fmt.Errorf("connector type '%s' not found", p.ConnectorType)
	}

	conf := vcert.Config{
		Credentials:   &auth,
		BaseUrl:       p.BaseURL,
		Zone:          p.Zone,
		ConnectorType: connectorType,
	}

	client, err := vcert.NewClient(&conf)
	if err != nil {
		return fmt.Errorf("could not connect to endpoint: %s", err)
	}

	p.Client = client

	return nil
}

// RevokeCertificate revokes a certificate in vcert (delete is not available via the api)
func (p *Proxy) RevokeCertificate(thumbprint string) error {
	revokeReq := &certificate.RevocationRequest{
		// CertificateDN: requestID,
		Thumbprint: thumbprint,
		Reason:     "key-compromise",
		Comments:   "revocation comment below",
		Disable:    false,
	}

	err := p.Client.RevokeCertificate(revokeReq)
	if err != nil {
		return err
	}

	output.Verbose("Successfully submitted revocation request for thumbprint %s", thumbprint)
	return nil
}

func sendCertificateRequest(c endpoint.Connector, enrollReq *certificate.Request) (requestID string, privateKey string, err error) {
	err = c.GenerateRequest(nil, enrollReq)
	if err != nil {
		return "", "", err
	}

	requestID, err = c.RequestCertificate(enrollReq)
	if err != nil {
		return "", "", err
	}

	pemBlock, err := certificate.GetPrivateKeyPEMBock(enrollReq.PrivateKey)
	if err != nil {
		return "", "", err
	}
	privateKey = string(pem.EncodeToMemory(pemBlock))

	output.Verbose("Successfully submitted certificate request. Will pickup certificate by ID %s", requestID)
	return requestID, privateKey, nil
}

// PrependPolicyRoot adds \Policy\ to the front of the zone string
func PrependPolicyRoot(zone string) string {
	zone = strings.TrimPrefix(zone, "\\")
	zone = strings.TrimPrefix(zone, "Policy\\")
	return prependVEDRoot("\\Policy\\" + zone)
}

func prependVEDRoot(zone string) string {
	zone = strings.TrimPrefix(zone, "\\")
	zone = strings.TrimPrefix(zone, "VED\\")
	return "\\VED\\" + zone
}
