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

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/newcontext/vault-venafi/config"
	"github.com/newcontext/vault-venafi/output"
	"github.com/newcontext/vault-venafi/vault"
	"github.com/newcontext/vault-venafi/vcert"

	"github.com/Venafi/vcert/pkg/certificate"
)

var vaultafi Vaultafi

func readConfigs() (*config.YAMLConfig, error) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configYAML, err := config.ReadConfig(userHomeDir, ConfigFile)
	if err != nil {
		return nil, err
	}

	return configYAML, nil
}

func configureVaultafi(usePKI bool) error {
	configYAML, err := readConfigs()
	if err != nil {
		return err
	}

	secretEngine := &vault.SecretEngine{
		BaseURL: configYAML.VaultBaseURL,
		Token:   configYAML.VaultToken,
		Path:    configYAML.VaultKVPath,
	}

	var vaultProxy vault.IProxy

	vaultProxy = &vault.KV{
		SecretEngine: secretEngine,
	}

	if usePKI {
		secretEngine.Path = configYAML.VaultPKIPath

		vaultProxy = &vault.PKI{
			SecretEngine: secretEngine,
			Role:         configYAML.VaultRole,
		}
	}

	vcertProxy := &vcert.Proxy{
		Username:      configYAML.VcertUsername,
		Password:      configYAML.VcertPassword,
		Zone:          configYAML.VcertZone,
		BaseURL:       configYAML.VcertBaseURL,
		ConnectorType: configYAML.ConnectorType,
	}

	vaultafi = Vaultafi{
		vault: vaultProxy,
		vcert: vcertProxy,
	}

	return nil
}

// Command represents a command line instruction from the user
type Command interface {
	validateFlags() error
	prepFlags()
	execute() error
}

func parseCommand() (Command, error) {
	// don't use the logger until it has been setup to write to file
	log.SetOutput(&NoopWriter{})

	if len(os.Args) < 2 {
		return &HelpCommand{}, nil
	}

	cmdArg := os.Args[1]

	var cmd Command
	switch cmdArg {
	case "create":
		cmd = &CreateCommand{}
	case "revoke":
		cmd = &RevokeCommand{}
	case "list":
		cmd = &ListCommand{}
	case "login":
		cmd = &LoginCommand{}
	case "-help", "-h":
		cmd = &HelpCommand{}
	default:
		return nil, fmt.Errorf("command not recognized: %s", cmdArg)
	}

	newArgs := []string{os.Args[0]}
	newArgs = append(newArgs, os.Args[2:]...)
	os.Args = newArgs

	cmd.prepFlags()
	flag.BoolVar(&config.Quiet, "quiet", false, "Suppress normal output to stdout.")

	flag.Parse()

	err := cmd.validateFlags()
	if err != nil {
		return nil, err
	}

	return cmd, nil
}

// HelpCommand implements the "help" cli command
type HelpCommand struct {
	Help string
}

func (cmd *HelpCommand) validateFlags() error {
	return nil
}

func (cmd *HelpCommand) prepFlags() {
	flag.StringVar(&cmd.Help, "help", "", "print usage")
}

func (cmd *HelpCommand) execute() error {
	output.HelpOutput(
		`Usage:
  vv [command]

Available commands:
  create   Generate a certificate and upload to Venafi
  revoke   Revoke a credential
  list     List certificates in each system
  login    Login to Vault with token, userpass or cert auth
`)

	return nil
}

// CreateCommand contains the information needed to construct a call to generate and store a cert
type CreateCommand struct {
	Name string

	CommonName         string                    // v,c
	SANDNS             stringSlice               // v
	KeyType            certificate.KeyType       // v
	KeyCurve           certificate.EllipticCurve // v
	OrganizationName   string                    // v,c
	OrganizationalUnit stringSlice               // v,c
	Country            string                    // v,c
	State              string                    // v,c
	Locality           string                    // v,c
	SANEmail           emailSlice                // v
	SANIP              ipSlice                   // v
	KeyPassword        string                    // v

	// -n, --name=              Name of the credential to generate
	// Name string // c

	// CommonName         string
	// SANDNS             stringSlice
	// KeyType            certificate.KeyType
	// KeyCurve           certificate.EllipticCurve
	// OrganizationName   string
	// OrganizationalUnit stringSlice
	// Country            string
	// State              string
	// Locality           string
	// SANEmail           emailSlice
	// SANIP              ipSlice
	// KeyPassword        string
	// AuthConfig         CVConfig

	// -t, --type=              Sets the credential type to generate. Valid types include 'password', 'user', 'certificate', 'ssh' and 'rsa'.
	// -O, --no-overwrite       Credential is not modified if stored value already exists
	NoOverwrite bool // c
	// -j, --output-json        Return response in JSON format
	// -k, --key-length=        [Certificate, SSH, RSA] Bit length of the generated key (Default: 2048)
	KeyLength int // c
	// -d, --duration=          [Certificate] Valid duration (in days) of the generated certificate (Default: 365)
	Duration int // c
	// -c, --common-name=       [Certificate] Common name of the generated certificate
	// CommonName string // c
	// -o, --organization=      [Certificate] OrganizationName of the generated certificate
	// OrganizationName string // c
	// -u, --organization-unit= [Certificate] Organization unit of the generated certificate
	// OrganizationalUnit string // c
	// -i, --locality=          [Certificate] Locality/city of the generated certificate
	// Locality string // c
	// -s, --state=             [Certificate] State/province of the generated certificate
	// State string // c
	// -y, --country=           [Certificate] Country of the generated certificate
	// Country string // c
	// -a, --alternative-name=  [Certificate] A subject alternative name of the generated certificate (may be specified multiple times)
	AlternativeName stringSlice // c
	// -g, --key-usage=         [Certificate] Key Usage extensions for the generated certificate (may be specified multiple times)
	KeyUsage stringSlice // c
	// -e, --ext-key-usage=     [Certificate] Extended Key Usage extensions for the generated certificate (may be specified multiple times)
	ExtKeyUsage stringSlice // c
	// --ca=                [Certificate] Name of CA used to sign the generated certificate
	CA string // c
	// --is-ca              [Certificate] The generated certificate is a certificate authority
	IsCA bool // c
	// --self-sign          [Certificate] The generated certificate will be self-signed
	SelfSign bool // c

	GenOnly bool
	Vault   bool
}

func (cmd *CreateCommand) validateFlags() error {
	if cmd.CommonName == "" && len(cmd.SANDNS) == 0 {
		return errors.New("you must have a common name or san-dns")
	}
	return nil
}

func (cmd *CreateCommand) prepFlags() {
	flag.StringVar(&cmd.Name, "name", "", "Vault Name")

	flag.StringVar(&cmd.CommonName, "cn", "", "(all) Common name")
	flag.Var(&cmd.SANDNS, "san-dns", "(Venafi) San DNS")
	flag.Var(&cmd.KeyType, "key-type", "(Venafi) Key type")
	flag.Var(&cmd.KeyCurve, "key-curve", "(Venafi) Key curve")
	flag.StringVar(&cmd.OrganizationName, "o", "", "(all) Organization Name")
	flag.Var(&cmd.OrganizationalUnit, "ou", "(all) Organizational Unit")
	flag.StringVar(&cmd.Country, "c", "", "(all) Country")
	flag.StringVar(&cmd.State, "st", "", "(all) State")
	flag.StringVar(&cmd.Locality, "l", "", "(all) Locality")
	flag.Var(&cmd.SANEmail, "san-email", "(Venafi) SAN Email")
	flag.Var(&cmd.SANIP, "san-ip", "(Venafi) SAN IP")
	flag.StringVar(&cmd.KeyPassword, "key-password", "", "(Venafi) Key Password")

	// -O, --no-overwrite       Credential is not modified if stored value already exists
	flag.BoolVar(&cmd.NoOverwrite, "no-overwrite", false, "(Vault) NoOverwrite")
	// -k, --key-length=        [Certificate, SSH, RSA] Bit length of the generated key (Default: 2048)
	flag.IntVar(&cmd.KeyLength, "key-length", 2048, "(Vault) KeyLength")
	// -d, --duration=          [Certificate] Valid duration (in days) of the generated certificate (Default: 365)
	flag.IntVar(&cmd.Duration, "duration", 365, "(Vault) Duration")
	// -a, --alternative-name=  [Certificate] A subject alternative name of the generated certificate (may be specified multiple times)
	flag.Var(&cmd.AlternativeName, "alternative-name", "(Vault) AlternativeName")
	// -g, --key-usage=         [Certificate] Key Usage extensions for the generated certificate (may be specified multiple times)
	flag.Var(&cmd.KeyUsage, "key-usage", "(Vault) KeyUsage")
	// -e, --ext-key-usage=     [Certificate] Extended Key Usage extensions for the generated certificate (may be specified multiple times)
	flag.Var(&cmd.ExtKeyUsage, "ext-key-usage", "(Vault) ExtKeyUsage")
	// --ca=                [Certificate] Name of CA used to sign the generated certificate
	flag.StringVar(&cmd.CA, "ca", "", "(Vault) CA")
	// --is-ca              [Certificate] The generated certificate is a certificate authority
	flag.BoolVar(&cmd.IsCA, "is-ca", false, "(Vault) IsCA")
	// --self-sign          [Certificate] The generated certificate will be self-signed
	flag.BoolVar(&cmd.SelfSign, "self-sign", false, "(Vault) SelfSign")

	flag.BoolVar(&cmd.GenOnly, "genonly", false, "(all) Only generate the cert. Do not copy it to the other platform. By default cert is copied from generated platform to other platform.")
	flag.BoolVar(&cmd.Vault, "vault", false, "(Vault) Generate the certificate on Vault PKI Secrets Engine. By default the certificate is generated on the Venafi platform.")
}

func (cmd *CreateCommand) execute() error {
	err := configureVaultafi(cmd.Vault)
	if err != nil {
		return err
	}

	generateFunc := vaultafi.createCertVenafi

	if cmd.Vault {
		generateFunc = vaultafi.createCertVault
	}

	err = vaultafi.vault.Login()
	if err != nil {
		return err
	}

	err = vaultafi.vcert.Login()
	if err != nil {
		return err
	}

	if cmd.Name == "" {
		cmd.Name = cmd.CommonName
	}

	return generateFunc(cmd.Name, cmd)
}

// RevokeCommand contains the information required to construct a call to delete a cert
type RevokeCommand struct {
	Name  string
	Vault bool
}

func (cmd *RevokeCommand) validateFlags() error {
	if cmd.Name == "" {
		return fmt.Errorf("name is required")
	}
	return nil
}

func (cmd *RevokeCommand) prepFlags() {
	flag.StringVar(&cmd.Name, "name", "", "Name")
	flag.BoolVar(&cmd.Vault, "vault", false, "Revoke the certificates on Vault PKI Secrets Engine and Venafi platform")
}

func (cmd *RevokeCommand) execute() error {
	err := configureVaultafi(cmd.Vault)
	if err != nil {
		return err
	}

	revokeFunc := vaultafi.revokeCertVenafi

	if cmd.Vault {
		revokeFunc = vaultafi.revokeCertVault
	}

	err = vaultafi.vault.Login()
	if err != nil {
		return err
	}

	err = vaultafi.vcert.Login()
	if err != nil {
		return err
	}

	return revokeFunc(cmd.Name)
}

// LoginCommand contains the information required to construct a call to log in to the Vault service
type LoginCommand struct {
	AuthMethod  string
	BaseURL     string
	Username    string
	Password    string
	Certificate string
	Method      string
	SaveToken   bool
}

func (cmd *LoginCommand) validateFlags() error {
	if cmd.BaseURL == "" {
		configYAML, err := readConfigs()
		if err != nil {
			return err
		}

		cmd.BaseURL = configYAML.VaultBaseURL
	}

	return nil
}

func (cmd *LoginCommand) prepFlags() {
	flag.StringVar(&cmd.AuthMethod, "method", "userpass", "Vault Auth Method")
	flag.StringVar(&cmd.Username, "username", "", "Username")
	flag.StringVar(&cmd.Password, "password", "", "Password")
	flag.StringVar(&cmd.Certificate, "certificate", "", "Certificate")
	flag.StringVar(&cmd.BaseURL, "url", "", "URL")
	flag.BoolVar(&cmd.SaveToken, "save", false, "Save token to config file")
}

func (cmd *LoginCommand) execute() error {
	secretEngine := &vault.SecretEngine{
		BaseURL:     cmd.BaseURL,
		AuthMethod:  cmd.AuthMethod,
		Username:    cmd.Username,
		Password:    cmd.Password,
		Certificate: cmd.Certificate,
	}

	err := secretEngine.Login()
	if err != nil {
		return err
	}

	if cmd.SaveToken {
		config.UpdateToken(ConfigFile, secretEngine.Client.Token())
		fmt.Println("Saved Access Token to config file")
	} else {
		fmt.Println("Access Token:", secretEngine.Client.Token())
	}

	return nil
}

// ListCommand contains the information required to construct a call to list certificates
type ListCommand struct {
	ByThumbprint bool
	ByCommonName bool
	ByPath       bool
	VaultPrefix  string
	VaultRoot    string
	VenafiPrefix string
	VenafiRoot   string
	VenafiLimit  int
	Vault        bool
}

func (cmd *ListCommand) validateFlags() error {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configYAML, err := config.ReadConfig(userHomeDir, ConfigFile)
	if err != nil {
		return err
	}

	if cmd.VenafiRoot == "" && configYAML.VcertZone != "" {
		cmd.VenafiRoot = vcert.PrependPolicyRoot(configYAML.VcertZone)
	}

	return nil
}

func (cmd *ListCommand) prepFlags() {
	flag.BoolVar(&cmd.ByThumbprint, "bythumbprint", false, "Compare by thumbprint. Note this will be slower due to the need to download each cert from Vault.")
	flag.BoolVar(&cmd.ByCommonName, "bycommonname", false, "Compare by certificate common name against Venafi and Vault.")
	flag.BoolVar(&cmd.ByPath, "bypath", false, "Compare by path")
	flag.StringVar(&cmd.VaultPrefix, "vaultprefix", "", "Vault prefix to strip from returned values")
	flag.StringVar(&cmd.VaultRoot, "vault-root", "", "Vault subpath to search")
	flag.StringVar(&cmd.VenafiPrefix, "venafi-prefix", "", "Venafi prefix to strip from returned values")
	flag.StringVar(&cmd.VenafiRoot, "venafi-root", "", "Venafi subpath to search")
	flag.IntVar(&cmd.VenafiLimit, "venafi-limit", 100, "(Default 100) Limits the number of Venafi results returned")
	flag.BoolVar(&cmd.Vault, "vault", false, "List the certificates on Vault PKI Secrets Engine and Venafi platform")
}

func (cmd *ListCommand) execute() error {
	err := configureVaultafi(cmd.Vault)
	if err != nil {
		return err
	}

	err = vaultafi.vcert.Login()
	if err != nil {
		return err
	}

	err = vaultafi.vault.Login()
	if err != nil {
		return err
	}

	_, err = vaultafi.listBoth(cmd)

	return err
}

// NoopWriter represents a Writer that just returns
type NoopWriter struct {
}

func (w *NoopWriter) Write(p []byte) (n int, err error) {
	return 0, nil
}

type stringSlice []string

func (ss *stringSlice) String() string {
	if len(*ss) == 0 {
		return ""
	}
	return strings.Join(*ss, "\n") + "\n"
}

func (ss *stringSlice) Set(value string) error {
	*ss = append(*ss, value)
	return nil
}

type ipSlice []net.IP

func (is *ipSlice) String() string {
	var ret string
	for _, s := range *is {
		ret += fmt.Sprintf("%s\n", s)
	}
	return ret
}

func (is *ipSlice) Set(value string) error {
	temp := net.ParseIP(value)
	if temp != nil {
		*is = append(*is, temp)
		return nil
	}
	return fmt.Errorf("failed to convert %s to an IP Address", value)
}

type emailSlice []string

func (es *emailSlice) String() string {
	var ret string
	for _, s := range *es {
		ret += fmt.Sprintf("%s\n", s)
	}
	return ret
}

func (es *emailSlice) Set(value string) error {
	if isValidEmailAddress(value) {
		*es = append(*es, value)
		return nil
	}
	return fmt.Errorf("failed to convert %s to an Email Address", value)
}

const emailRegex = "[[:alnum:]][\\w\\.-]*[[:alnum:]]@[[:alnum:]][\\w\\.-]*[[:alnum:]]\\.[[:alpha:]][a-z\\.]*[[:alpha:]]$"

func isValidEmailAddress(email string) bool {
	reg := regexp.MustCompile(emailRegex)
	return reg.FindStringIndex(email) != nil
}
