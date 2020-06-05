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

package config

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	yaml "gopkg.in/yaml.v2"
)

// VaultafiLogFilename is the name of the application log file
const VaultafiLogFilename string = "vault-venafi.log"

// VERBOSE contains the int32 value for verbose logging
var VERBOSE int32 = 4

// INFO contains the int32 value for info-level logging
var INFO int32 = 3

// STATUS contains the int32 value for status-level logging
var STATUS int32 = 2

// ERROR contains the int32 value for error-level logging
var ERROR int32 = 1

// LogLevel represents the desired log verbosity
var LogLevel = STATUS

// Quiet is a flag to suppress normal output to stdout, but not the log
var Quiet = false

// YAMLConfig contains the configuration values and yaml tags for the config file
type YAMLConfig struct {
	VCloudAPIKey  string `yaml:"vcloud_api_key"`
	VcertUsername string `yaml:"vcert_username"`
	VcertPassword string `yaml:"vcert_password"`
	VcertZone     string `yaml:"vcert_zone"`
	VcertBaseURL  string `yaml:"vcert_base_url"`
	ConnectorType string `yaml:"connector_type"`
	VaultToken    string `yaml:"vault_token"`
	VaultBaseURL  string `yaml:"vault_base_url"`
	VaultKVPath   string `yaml:"vault_kv_path"`
	VaultPKIPath  string `yaml:"vault_pki_path"`
	VaultRole     string `yaml:"vault_role"`
	LogLevel      string `yaml:"log_level"`

	SkipTLSValidation bool `yaml:"skip_tls_validation"`
}

// ReadConfig reads the configuration file and returns the information in a struct
func ReadConfig(homedir string, path string) (*YAMLConfig, error) {
	configpath := filepath.Join(homedir, path)
	tt := YAMLConfig{}
	file, err := ioutil.ReadFile(configpath)
	if err != nil {
		return nil, err
	}

	err = yaml.UnmarshalStrict(file, &tt)
	if err != nil {
		return nil, err
	}
	if tt.ConnectorType == "" {
		tt.ConnectorType = "tpp"
	}

	switch tt.LogLevel {
	case "error":
		LogLevel = ERROR
	case "info":
		LogLevel = INFO
	case "verbose":
		LogLevel = VERBOSE
	case "status":
		LogLevel = STATUS
	}

	logfilePath := VaultafiLogFilename
	f, err := os.OpenFile(logfilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("error opening log file: %v", err)
	}

	log.SetOutput(f)
	return &tt, nil
}

// UpdateToken updates the token value in the config file
func UpdateToken(path string, token string) error {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configpath := filepath.Join(userHomeDir, path)
	tt := YAMLConfig{}

	file, err := ioutil.ReadFile(configpath)
	if err != nil {
		return err
	}

	err = yaml.UnmarshalStrict(file, &tt)
	if err != nil {
		return err
	}

	tt.VaultToken = token

	b, err := yaml.Marshal(tt)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(configpath, b, os.ModePerm)
	if err != nil {
		return err
	}

	return nil
}

// WriteConfig is for initializing a default config file
func WriteConfig() {}
