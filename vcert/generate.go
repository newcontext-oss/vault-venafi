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

// This file contains the code supporting the "Generate" function.  It's in its own file to
// try to make it easier to understand.

import (
	"crypto/x509/pkix"
	"fmt"
	"net"
	"time"

	"github.com/Venafi/vcert/pkg/certificate"
)

// CertArgs holds the arguments for certificate creation in vcert
type CertArgs struct {
	Name               string
	CommonName         string
	OrganizationName   string
	SANDNS             []string
	KeyCurve           certificate.EllipticCurve
	OrganizationalUnit []string
	Origin             string
	Country            string
	State              string
	Locality           string
	SANEmail           []string
	SANIP              []net.IP
	KeyPassword        string
}

// GenerateCertificate generates a certificate in vcert
func (p *Proxy) GenerateCertificate(args *CertArgs) (*certificate.PEMCollection, error) {
	req, err := buildGenerateRequest(args)
	if err != nil {
		return nil, err
	}

	requestID, privateKey, err := sendCertificateRequest(p.Client, req)
	if err != nil {
		return nil, err
	}

	pickupReq := &certificate.Request{
		PickupID: requestID,
		Timeout:  180 * time.Second,
	}

	pcc, err := p.Client.RetrieveCertificate(pickupReq)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve certificate using requestId %s: %s", requestID, err)
	}
	pcc.PrivateKey = privateKey
	return pcc, nil
}

func buildGenerateRequest(args *CertArgs) (*certificate.Request, error) {
	r := &certificate.Request{}
	r.FriendlyName = args.Name

	subject := pkix.Name{}
	if args.CommonName != "" {
		subject.CommonName = args.CommonName
	}
	if args.OrganizationName != "" {
		subject.Organization = []string{args.OrganizationName}
	}
	if len(args.SANDNS) != 0 {
		r.DNSNames = args.SANDNS
	}
	r.KeyCurve = args.KeyCurve
	if len(args.OrganizationalUnit) > 0 {
		subject.OrganizationalUnit = args.OrganizationalUnit
	}
	if args.Country != "" {
		subject.Country = []string{args.Country}
	}
	if args.State != "" {
		subject.Province = []string{args.State}
	}
	if args.Locality != "" {
		subject.Locality = []string{args.Locality}
	}
	if len(args.SANEmail) > 0 {
		r.EmailAddresses = args.SANEmail
	}
	if len(args.SANIP) > 0 {
		r.IPAddresses = args.SANIP
	}
	if args.KeyPassword == "" {
		r.KeyPassword = args.KeyPassword
	}

	r.Subject = subject

	r.CustomFields = append(r.CustomFields, certificate.CustomField{
		Type:  certificate.CustomFieldOrigin,
		Name:  "Origin",
		Value: origin,
	})

	return r, nil
}
