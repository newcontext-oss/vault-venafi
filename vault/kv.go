package vault

import (
	"encoding/json"
	"errors"
	"fmt"
)

// KV contains the config information for the Vault KV request proxy
type KV struct {
	*SecretEngine
}

// CreateCertificate returns "Not Implemented" error. Required for IProxy interface
func (kv *KV) CreateCertificate(name string, params Parameters) (map[string]interface{}, error) {
	return nil, errors.New("not implemented")
}

// PutCertificate creates a new certificate in Vault
func (kv *KV) PutCertificate(name string, cred Credential) error {
	data := map[string]interface{}{
		"data": map[string]interface{}{
			"name":        name,
			"common_name": cred.CommonName,
			"certificate": cred.Certificate,
			"chain":       cred.Chain,
			"private_key": cred.PrivateKey,
		},
	}

	path := formatDataPath(kv.Path, name, "data")

	_, err := kv.Client.Logical().Write(path, data)
	if err != nil {
		return err
	}

	return nil
}

// RevokeCertificate revokes a certificate in Vault K/V
func (kv *KV) RevokeCertificate(name string) error {
	path := formatDataPath(kv.Path, name, "data")

	_, err := kv.Client.Logical().Delete(path)
	if err != nil {
		return err
	}

	return nil
}

// GetCertificate returns a certificate from Vault
func (kv *KV) GetCertificate(name string) (Credential, error) {
	var cert Credential

	path := formatDataPath(kv.Path, name, "data")

	resp, err := kv.Client.Logical().Read(path)
	if err != nil {
		return cert, err
	}
	if resp == nil {
		return cert, fmt.Errorf("failed to get certificate: %s", name)
	}

	// convert map to json
	jsonString, _ := json.Marshal(resp.Data["data"])

	// convert json to struct
	json.Unmarshal(jsonString, &cert)

	return cert, nil
}

// ListCertificates returns a certificate from Vault
func (kv *KV) ListCertificates() ([]Credential, error) {
	path := formatDataPath(kv.Path, "", "metadata")

	resp, err := kv.Client.Logical().List(path)
	if err != nil {
		return nil, err
	}

	keys := resp.Data["keys"].([]interface{})
	certs := []Credential{}

	for _, key := range keys {
		cert, err := kv.GetCertificate(key.(string))
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
