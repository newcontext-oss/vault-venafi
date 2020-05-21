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
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testToken = "dev"
var testBaseURL = "http://localhost:8200"

func TestValidConfig(t *testing.T) {
	defer cleanup()

	client, err := newClient(testBaseURL, testToken)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Nil(t, err, "It should create a client from a valid config")
	assert.Equal(t, testToken, client.Token(), "It should use the configured access token")
	assert.Equal(t, testBaseURL, client.Address(), "It should use the configured base URL")
}

func TestUseDefaults(t *testing.T) {
	defer cleanup()

	client, err := newClient("", "")
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Nil(t, err, "It should create a client from an empty config")
	assert.Equal(t, "", client.Token(), "It should have an empty token")
	assert.Equal(t, "https://127.0.0.1:8200", client.Address(), "It should use the default local endpoint")
}

func TestUseEnvVars(t *testing.T) {
	defer cleanup()

	os.Setenv("VAULT_ADDR", "http://test-host:8200")
	os.Setenv("VAULT_TOKEN", "test-token")

	client, err := newClient("", "")
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Nil(t, err, "It should create a client from an empty config")
	assert.Equal(t, "test-token", client.Token(), "It should use the \"VAULT_TOKEN\" environment variable")
	assert.Equal(t, "http://test-host:8200", client.Address(), "It should use the \"VAULT_ADDR\" environment variable")
}

func TestGetThumbprint(t *testing.T) {
	var originalCert = "-----BEGIN CERTIFICATE-----\nMIIDejCCAmICCQCOfKt6rlmQHzANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJD\nTzELMAkGA1UECAwCU1QxCzAJBgNVBAcMAkxPMQswCQYDVQQKDAJPTzEhMB8GCSqG\nSIb3DQEJARYSeW91QHlvdXJkb21haW4uY29tMRIwEAYDVQQDDAlsb2NhbGhvc3Qx\nEjAQBgNVBAMMCWRldi5sb2NhbDAeFw0yMDA0MTUyMDU3MDVaFw0yMDA1MTUyMDU3\nMDVaMH8xCzAJBgNVBAYTAkNPMQswCQYDVQQIDAJTVDELMAkGA1UEBwwCTE8xCzAJ\nBgNVBAoMAk9PMSEwHwYJKoZIhvcNAQkBFhJ5b3VAeW91cmRvbWFpbi5jb20xEjAQ\nBgNVBAMMCWxvY2FsaG9zdDESMBAGA1UEAwwJZGV2LmxvY2FsMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzDM2RyDK0jipWRVmAMeYhDrZ2CJNVdy0P8d4\nNVTYAiwoXnRWwNkKLFFWK4MyuN54RFjafVrLNX9ZGakXqm/9NPXPZiljJIkVFI3P\nNYhNbwk19GaD1se7ncYQJTdeg2jzLeXAraTCIsCy+xPCVC97h6U7vS41KV9yfNos\nWZhgDWMmdCMvzPyrV6z4rZiRfgNNyaaHHPprCCOP6mpHwRfd0PykDA3keQ2UGjMh\n/62PHvid3Vj/y6+mMDZ3R1AZt2vN2FyTssUEBQbuJP5qYW5YszcY79J+TLmCvS9n\n+Qwm4sw33WYDXZ3DGTI/ZFc4LwLV6KOKrKiEb3BjFyFFzDLl2wIDAQABMA0GCSqG\nSIb3DQEBCwUAA4IBAQDGfdc73t8MnGEADhpatlr+W4u/wg9zgxvV6EMO5K6FGFAb\n0o5DP2pFYOgXCqjhKy/U979KIoMN7lXIUN9SSyQi0LGkza7xcOUATiTaN88Prl8f\nRA1PIbyA2rvS6i0R17cp1P3tR/f58rvuMnU0oqyZzR5DcQDb5ejtJFvh5pxoPXz6\nVWw+3+PDfoiECNIhiodUvxWBzy0QycESaLupwsZQBWAkfOeh/h5/boGA0gzAWkkQ\nySiRgfjR+dwzb7Kcf+FyNhbmWyuBKB7iGZwGiXf76kPHk+k3ubdFweFoZJFjIhTQ\n4VvCZdkfIVayjqGBRBxHNiwG1Pow+73Kfe1qYb8k\n-----END CERTIFICATE-----"
	var strippedCert = "MIIDejCCAmICCQCOfKt6rlmQHzANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJDTzELMAkGA1UECAwCU1QxCzAJBgNVBAcMAkxPMQswCQYDVQQKDAJPTzEhMB8GCSqGSIb3DQEJARYSeW91QHlvdXJkb21haW4uY29tMRIwEAYDVQQDDAlsb2NhbGhvc3QxEjAQBgNVBAMMCWRldi5sb2NhbDAeFw0yMDA0MTUyMDU3MDVaFw0yMDA1MTUyMDU3MDVaMH8xCzAJBgNVBAYTAkNPMQswCQYDVQQIDAJTVDELMAkGA1UEBwwCTE8xCzAJBgNVBAoMAk9PMSEwHwYJKoZIhvcNAQkBFhJ5b3VAeW91cmRvbWFpbi5jb20xEjAQBgNVBAMMCWxvY2FsaG9zdDESMBAGA1UEAwwJZGV2LmxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzDM2RyDK0jipWRVmAMeYhDrZ2CJNVdy0P8d4NVTYAiwoXnRWwNkKLFFWK4MyuN54RFjafVrLNX9ZGakXqm/9NPXPZiljJIkVFI3P\nNYhNbwk19GaD1se7ncYQJTdeg2jzLeXAraTCIsCy+xPCVC97h6U7vS41KV9yfNosWZhgDWMmdCMvzPyrV6z4rZiRfgNNyaaHHPprCCOP6mpHwRfd0PykDA3keQ2UGjMh/62PHvid3Vj/y6+mMDZ3R1AZt2vN2FyTssUEBQbuJP5qYW5YszcY79J+TLmCvS9n+Qwm4sw33WYDXZ3DGTI/ZFc4LwLV6KOKrKiEb3BjFyFFzDLl2wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQDGfdc73t8MnGEADhpatlr+W4u/wg9zgxvV6EMO5K6FGFAb0o5DP2pFYOgXCqjhKy/U979KIoMN7lXIUN9SSyQi0LGkza7xcOUATiTaN88Prl8fRA1PIbyA2rvS6i0R17cp1P3tR/f58rvuMnU0oqyZzR5DcQDb5ejtJFvh5pxoPXz6VWw+3+PDfoiECNIhiodUvxWBzy0QycESaLupwsZQBWAkfOeh/h5/boGA0gzAWkkQySiRgfjR+dwzb7Kcf+FyNhbmWyuBKB7iGZwGiXf76kPHk+k3ubdFweFoZJFjIhTQ4VvCZdkfIVayjqGBRBxHNiwG1Pow+73Kfe1qYb8k"

	expectedBase64, err := base64.StdEncoding.DecodeString(strippedCert)
	if err != nil {
		log.Fatal([20]byte{}, err)
	}

	expectedSha, err := sha1.Sum(expectedBase64), nil

	sha, err := GetThumbprint(originalCert)

	assert.Nil(t, err, "It should get the thumbprint without errors")
	assert.Equal(t, sha, expectedSha, "It should generate a thumbprint from the certificate")
}

func TestFormatDataPath(t *testing.T) {
	path := "secret/test/path"
	expected := "secret/data/test/path/cert"
	actual := formatDataPath(path, "cert", "data")

	assert.Equal(t, expected, actual)

	path = "secret/test/cert"
	expected = "secret/metadata/test/cert"
	actual = formatDataPath(path, "", "metadata")

	assert.Equal(t, expected, actual)
}

// Reset variables before each test
func cleanup() {
	os.Unsetenv("VAULT_ADDR")
	os.Unsetenv("VAULT_TOKEN")
}
