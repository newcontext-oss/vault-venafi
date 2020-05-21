package vault

import (
	"encoding/json"
	"errors"
	"fmt"
)

// PKI contains the config information for the Vault PKI request proxy
type PKI struct {
	*SecretEngine
	Role string
}

// CreateCertificate creates a new certificate in Vault PKI
func (pki *PKI) CreateCertificate(name string, params Parameters) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"common_name": params.CommonName,
		"ttl":         params.Duration,
	}

	// Create certificate in PKI secrets engine
	resp, err := pki.Client.Logical().Write("/pki/issue/"+pki.Role, data)
	if err != nil {
		return nil, err
	}

	data = map[string]interface{}{
		"data": map[string]string{
			"name":          name,
			"common_name":   params.CommonName,
			"certificate":   resp.Data["certificate"].(string),
			"private_key":   resp.Data["private_key"].(string),
			"serial_number": resp.Data["serial_number"].(string),
			"role":          pki.Role,
		},
	}

	path := formatDataPath(pki.Path, name, "data")

	// Map the certificate name to serial number in K/V secrets engine
	_, err = pki.Client.Logical().Write(path, data)
	if err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// RevokeCertificate revokes a certificate in Vault
func (pki *PKI) RevokeCertificate(name string) error {
	cert, err := pki.GetCertificate(name)
	if err != nil {
		return err
	}

	data := map[string]interface{}{
		"serial_number": cert.Serial,
	}

	_, err = pki.Client.Logical().Write("/pki/revoke/", data)
	if err != nil {
		return err
	}

	path := formatDataPath(pki.Path, name, "data")

	_, err = pki.Client.Logical().Delete(path)
	if err != nil {
		return err
	}

	return nil
}

// PutCertificate returns "Not Implemented" error. Required for IProxy interface
func (pki *PKI) PutCertificate(name string, cred Credential) error {
	return errors.New("not implemented")
}

// GetCertificate returns a certificate from Vault
func (pki *PKI) GetCertificate(name string) (Credential, error) {
	var cert Credential

	path := formatDataPath(pki.Path, name, "data")

	// Get the certificate serial number in K/V secrets engine
	resp, err := pki.Client.Logical().Read(path)
	if err != nil {
		return cert, err
	}
	if resp == nil {
		return cert, fmt.Errorf("failed to get certificate: %s", name)
	} else if resp.Data["data"] == nil {
		return cert, nil
	}

	serial := resp.Data["data"].(map[string]interface{})["serial_number"].(string)

	// Check certificate is in PKI secrets engine
	_, err = pki.Client.Logical().Read("/pki/cert/" + string(serial))
	if err != nil {
		return cert, err
	}

	// convert map to json
	jsonString, _ := json.Marshal(resp.Data["data"])

	// convert json to struct
	json.Unmarshal(jsonString, &cert)

	return cert, nil
}

// ListCertificates returns a certificate from Vault
func (pki *PKI) ListCertificates() ([]Credential, error) {
	path := formatDataPath(pki.Path, "", "metadata")

	resp, err := pki.Client.Logical().List(path)
	if err != nil {
		return nil, err
	}

	keys := resp.Data["keys"].([]interface{})
	certs := []Credential{}

	for _, key := range keys {
		cert, err := pki.GetCertificate(key.(string))
		if err != nil {
			return certs, err
		}
		if cert.Name == "" {
			continue
		}

		certs = append(certs, cert)
	}

	return certs, nil
}
