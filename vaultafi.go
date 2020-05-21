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
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/newcontext/vault-venafi/vault"
	"github.com/newcontext/vault-venafi/vcert"

	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/newcontext/vault-venafi/output"
)

// ConfigFile is the configuration file name
var ConfigFile = ".vault-venafi.conf"

// Vaultafi represents an object that manipulates both vault and vcert
type Vaultafi struct {
	vault vault.IProxy
	vcert vcert.IProxy
}

func (v *Vaultafi) createCertVenafi(name string, cmd *CreateCommand) error {
	output.Status("Creating on Venafi '%s'\n", cmd.Name)
	// we assume that login has already been done on vault
	args := &vcert.CertArgs{
		Name:               cmd.Name,
		CommonName:         cmd.CommonName,
		OrganizationName:   cmd.OrganizationName,
		SANDNS:             cmd.SANDNS,
		KeyCurve:           cmd.KeyCurve,
		OrganizationalUnit: cmd.OrganizationalUnit,
		Country:            cmd.Country,
		State:              cmd.State,
		Locality:           cmd.Locality,
		SANEmail:           cmd.SANEmail,
		SANIP:              cmd.SANIP,
		KeyPassword:        cmd.KeyPassword,
	}
	resp, err := v.vcert.GenerateCertificate(args)
	if err != nil {
		return err
	}

	credential := vault.Credential{
		Name:        cmd.Name,
		CommonName:  cmd.CommonName,
		Certificate: resp.Certificate,
		PrivateKey:  resp.PrivateKey,
		Chain:       resp.Chain,
	}

	output.Status("Uploading to Vault '%s'\n", cmd.Name)
	err = v.vault.PutCertificate(cmd.Name, credential)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vaultafi) createCertVault(name string, cmd *CreateCommand) error {
	parameters := vault.Parameters{
		KeyLength:        cmd.KeyLength,
		CommonName:       cmd.CommonName,
		Organization:     cmd.OrganizationName,
		OrganizationUnit: strings.Join(cmd.OrganizationalUnit, ","),
		Locality:         cmd.Locality,
		State:            cmd.State,
		Country:          cmd.Country,
		AlternativeNames: cmd.AlternativeName,
		ExtendedKeyUsage: cmd.ExtKeyUsage,
		KeyUsage:         cmd.KeyUsage,
		Duration:         cmd.Duration,
		Ca:               cmd.CA,
		SelfSign:         cmd.SelfSign,
		IsCA:             cmd.IsCA,
	}

	output.Status("Creating on Vault '%s'\n", name)
	resp, err := v.vault.CreateCertificate(name, parameters)
	if err != nil {
		return err
	}

	certificate := resp["certificate"].(string)
	privateKey := resp["private_key"].(string)

	output.Status("Uploading To Venafi '%s'\n", name)
	err = v.vcert.PutCertificate(name, certificate, privateKey)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vaultafi) revokeCertVenafi(name string) error {
	cert, err := v.vault.GetCertificate(name)
	if err != nil {
		return err
	}

	tp, err := vault.GetThumbprint(cert.Certificate)
	if err != nil {
		return err
	}
	tp2 := hex.EncodeToString(tp[:])

	output.Status("Revoking From Venafi '%s'\n", name)
	err = v.vcert.RevokeCertificate(tp2)
	if err != nil {
		return err
	}

	output.Status("Revoking From Vault '%s'\n", name)
	err = v.vault.RevokeCertificate(name)
	if err != nil {
		return err
	}

	return err
}

func (v *Vaultafi) revokeCertVault(name string) error {
	cert, err := v.vault.GetCertificate(name)
	if err != nil {
		return err
	}

	tp, err := vault.GetThumbprint(cert.Certificate)
	if err != nil {
		return err
	}
	tp2 := hex.EncodeToString(tp[:])

	output.Status("Revoking From Venafi '%s'\n", name)
	err = v.vcert.RevokeCertificate(tp2)
	if err != nil {
		return err
	}

	output.Status("Revoking From Vault '%s'\n", name)
	err = v.vault.RevokeCertificate(name)
	if err != nil {
		return err
	}

	return err
}

func (v *Vaultafi) listBoth(args *ListCommand) ([]CertCompareData, error) {
	output.Status("LISTING...\n")

	certInfo, err := v.vcert.ListCertificates(args.VenafiLimit, args.VenafiRoot)
	if err != nil {
		return []CertCompareData{}, err
	}

	list, err := v.vault.ListCertificates()
	if err != nil {
		return []CertCompareData{}, err
	}

	certs := []vault.Credential{}
	for _, item := range list {
		if strings.HasPrefix(item.Name, args.VaultRoot) {
			certs = append(certs, item)
		}
	}

	var ct ComparisonStrategy
	switch {
	case args.ByThumbprint:
		ct = &ThumbprintStrategy{getCertificate: v.vault.GetCertificate}
	case args.ByPath:
		ct = &PathStrategy{leftPrefix: joinRoot(args.VenafiRoot, args.VenafiPrefix, "\\"), rightPrefix: joinRoot(args.VaultRoot, args.VaultPrefix, "/")}
	default:
		ct = &CommonNameStrategy{}
	}
	data := compareCerts(ct, certInfo, certs, "", "")

	printCertsPretty(ct, data)

	e, ok := ct.(processErrors)
	if ok {
		for _, each := range e.getErrors() {
			output.Errorf("%s\n", each)
		}
	}
	if len(certInfo) == args.VenafiLimit {
		output.Errorf("The Venafi limit was hit, consider increasing -vlimit to increase the number of allowed records.\n")
	}

	return data, nil
}

func joinRoot(a, b, sep string) string {
	a = strings.TrimSuffix(a, sep)
	b = strings.TrimPrefix(b, sep)
	if a == "" {
		return b
	}
	return a + sep + b
}

func printCerts(data []CertCompareData) {
	for i, d := range data {
		output.Verbose("%d %+v\n", i, d)
	}
}

// ComparisonStrategy defines the interface for comparing credentials
type ComparisonStrategy interface {
	leftGet(l certificate.CertificateInfo) string
	rightGet(r vault.Credential) string
	leftTransform(in string) string
	rightTransform(in string) string
}

func buildCompareTransform(tct ComparisonStrategy) func(certificate.CertificateInfo, vault.Credential) int {
	return func(l certificate.CertificateInfo, r vault.Credential) int {
		return compareTransform(l, r, tct)
	}
}

func compareTransform(l certificate.CertificateInfo, r vault.Credential, tct ComparisonStrategy) int {
	commonName := tct.leftGet(l)
	vaultName := tct.rightGet(r)

	commonName = tct.leftTransform(commonName)
	vaultName = tct.rightTransform(vaultName)

	cmpVal := strings.Compare(commonName, vaultName)

	output.Verbose("compare commonName %s with vaultName %s out %d\n", commonName, vaultName, cmpVal)
	return cmpVal
}

func compareCerts(ct ComparisonStrategy, certInfo []certificate.CertificateInfo, items []vault.Credential, leftPrefix, rightPrefix string) []CertCompareData {
	cc := &DefaultCertCollector{}

	cmpTransform := buildCompareTransform(ct)
	compareLists(certInfo, items, cmpTransform, cc, ct)

	ps, ok := ct.(postSort)
	if ok {
		ps.postSort(cc.data)
	}

	printCerts(cc.data)
	return cc.data
}

// CertCompareData holds the necessary data for comparing certs
type CertCompareData struct {
	Left  *certificate.CertificateInfo
	Right *vault.Credential
}

func (c CertCompareData) String() string {
	out := ""
	if c.Left != nil {
		out += fmt.Sprintf(" Left:%+v ", *c.Left)
	} else {
		out += " Left: nil "
	}
	if c.Right != nil {
		out += fmt.Sprintf(" Right:%+v ", *c.Right)
	} else {
		out += " Right: nil "
	}
	return out
}

// DefaultCertCollector is a simple collector of cert comparison data
type DefaultCertCollector struct {
	data []CertCompareData
}

// CertificateInfo appends a cert from vcert to the collector
func (m *DefaultCertCollector) CertificateInfo(item certificate.CertificateInfo) {
	m.data = append(m.data, CertCompareData{Left: &item})
}

// CertificateMetadata appends a cert from vault to the collector
func (m *DefaultCertCollector) CertificateMetadata(item vault.Credential) {
	m.data = append(m.data, CertCompareData{Right: &item})
}

// Equals compares a cert from vcert to one from vault for identity
func (m *DefaultCertCollector) Equals(ci certificate.CertificateInfo, cm vault.Credential) {
	m.data = append(m.data, CertCompareData{Left: &ci, Right: &cm})
}

// CertCollector collects the comparison output
type CertCollector interface {
	// CertificateInfo handles a Venafi non-match
	CertificateInfo(certificate.CertificateInfo)
	// CertificateMetadata handles a Vault non-match
	CertificateMetadata(vault.Credential)
	// Equals handles certificates that match
	Equals(certificate.CertificateInfo, vault.Credential)
}

func compareLists(
	l []certificate.CertificateInfo,
	r []vault.Credential,
	comparison func(certificate.CertificateInfo, vault.Credential) int,
	collector CertCollector,
	tct ComparisonStrategy) {
	sort.SliceStable(l, func(i, j int) bool {
		a := tct.leftGet(l[i])
		b := tct.leftGet(l[j])
		a = tct.leftTransform(a)
		b = tct.leftTransform(b)
		return a < b
	})

	sort.SliceStable(r, func(i, j int) bool {
		a := tct.rightGet(r[i])
		b := tct.rightGet(r[j])
		a = tct.rightTransform(a)
		b = tct.rightTransform(b)
		return a < b
	})

	// print the sorted lists using get
	for _, item := range l {
		after := tct.leftTransform(tct.leftGet(item))
		output.Verbose("left %s", after)
	}
	for _, item := range r {
		after := tct.rightTransform(tct.rightGet(item))
		output.Verbose("right %s", after)
	}

	compareSortedLists(l, r, comparison, collector)
}

func compareSortedLists(
	l []certificate.CertificateInfo,
	r []vault.Credential,
	comparison func(certificate.CertificateInfo, vault.Credential) int,
	collector CertCollector) {
	i := 0
	j := 0
	n1 := len(l)
	n2 := len(r)

	for i < n1 && j < n2 {
		cmp := comparison(l[i], r[j])
		if cmp < 0 {
			collector.CertificateInfo(l[i])
			i++
		} else if cmp == 0 {
			collector.Equals(l[i], r[j])
			i++
			j++
		} else {
			collector.CertificateMetadata(r[j])
			j++
		}
	}

	for i < n1 {
		collector.CertificateInfo(l[i])
		i++
	}

	for j < n2 {
		collector.CertificateMetadata(r[j])
		j++
	}
}

// CommonNameStrategy with its methods, represents the strategy to normalize cert names
type CommonNameStrategy struct {
	leftPrefix  string
	rightPrefix string
}

func (t *CommonNameStrategy) leftGet(l certificate.CertificateInfo) string {
	return l.CN
}

func (t *CommonNameStrategy) rightGet(r vault.Credential) string {
	return r.CommonName
}

func (t *CommonNameStrategy) leftTransform(in string) string {
	return strings.TrimPrefix(in, t.leftPrefix)
}

func (t *CommonNameStrategy) rightTransform(in string) string {
	return vaultTransform(strings.TrimPrefix(in, t.rightPrefix))
}

func (t *CommonNameStrategy) headers() []string {
	return []string{"VENAFI", "VAULT"}
}

func (t *CommonNameStrategy) values(l *certificate.CertificateInfo, r *vault.Credential) []string {
	left := ""
	right := ""
	if l != nil {
		left = t.leftGet(*l)
	}
	if r != nil {
		right = t.rightGet(*r)
	}
	return []string{left, right}
}

// ThumbprintStrategy handles cert thumbprints
type ThumbprintStrategy struct {
	leftPrefix      string
	getCertificate  func(name string) (vault.Credential, error)
	thumbprintCache map[string]string
	errors          []error
}

func (t *ThumbprintStrategy) leftGet(l certificate.CertificateInfo) string {
	return l.Thumbprint
}

func (t *ThumbprintStrategy) rightGet(r vault.Credential) string {
	in := r.Name

	// we check if this path is already in the thumbprint cache, and return it right away if it is
	i, ok := t.cache()[in]
	if ok {
		return i
	}
	// we do a get on cert name to get a cert
	cert, err := t.getCertificate(in)
	if err != nil {
		t.errors = append(t.errors, err)
	}

	// then, from the cert we calculate the thumbprint
	certStr := cert.Certificate
	tp, err := vault.GetThumbprint(certStr)
	if err != nil {
		t.errors = append(t.errors, err)
	}
	tp2 := hex.EncodeToString(tp[:])
	output.Verbose("thumbprint %s path %s", tp2, in)
	// then we store that thumbprint in the cache
	t.cache()[in] = tp2
	// and we return that thumbprint
	return tp2
}

func (t *ThumbprintStrategy) leftTransform(in string) string {
	return strings.ToUpper(strings.TrimPrefix(in, t.leftPrefix))
}

func (t *ThumbprintStrategy) rightTransform(in string) string {
	return strings.ToUpper(strings.TrimPrefix(in, t.leftPrefix))
}

func (t *ThumbprintStrategy) headers() []string {
	return []string{"VENAFI", "VAULT", "THUMBPRINT"}
}

func (t *ThumbprintStrategy) cache() map[string]string {
	if t.thumbprintCache == nil {
		t.thumbprintCache = map[string]string{}
	}
	return t.thumbprintCache
}

func (t *ThumbprintStrategy) getErrors() []error {
	return t.errors
}

func (t *ThumbprintStrategy) values(l *certificate.CertificateInfo, r *vault.Credential) []string {
	thumbprint := ""
	left := ""
	right := ""

	if l != nil {
		left = l.CN
		thumbprint = l.Thumbprint
	}
	if r != nil {
		right = r.Name

		i, ok := t.cache()[r.Name]
		if ok {
			thumbprint = i
		}
	}
	return []string{left, right, strings.ToLower(thumbprint)}
}

func (t *ThumbprintStrategy) postSort(l []CertCompareData) {
	cmp := func(i, j int) bool {
		a := l[i]
		b := l[j]
		if a.Left != nil && b.Left == nil {
			return false
		} else if a.Left == nil && b.Left != nil {
			return true
		} else if a.Left != nil && b.Left != nil {
			aID := a.Left.ID
			bID := b.Left.ID
			if aID < bID {
				return true
			}
		}

		if a.Right != nil && b.Right == nil {
			return false
		} else if a.Right == nil && b.Right != nil {
			return true
		}
		if a.Right != nil && b.Right != nil {
			aID := a.Right.Name
			bID := b.Right.Name
			return aID < bID
		}
		return !(a.Right == nil && b.Right == nil)
	}

	sort.SliceStable(l, func(i, j int) bool {
		return !cmp(i, j)
	})
}

// PathStrategy handles normalization of file paths
type PathStrategy struct {
	leftPrefix  string
	rightPrefix string
}

func (t *PathStrategy) leftGet(l certificate.CertificateInfo) string {
	return l.ID
}

func (t *PathStrategy) rightGet(r vault.Credential) string {
	return r.Name
}

func (t *PathStrategy) leftTransform(in string) string {
	return t.normalize(in, t.leftPrefix)
}

func (t *PathStrategy) rightTransform(in string) string {
	return t.normalize(in, t.rightPrefix)
}

func (t *PathStrategy) normalize(in string, prefix string) string {
	prefix = strings.ReplaceAll(prefix, "\\", "/")
	in = strings.ReplaceAll(in, "\\", "/")
	return strings.TrimPrefix(strings.TrimPrefix(in, prefix), "/")
}

func (t *PathStrategy) leftDisplay(l certificate.CertificateInfo) string {
	return l.ID
}

func (t *PathStrategy) rightDisplay(r vault.Credential) string {
	return r.Name
}

func (t *PathStrategy) headers() []string {
	return []string{"VENAFI", "VAULT"}
}

func (t *PathStrategy) values(l *certificate.CertificateInfo, r *vault.Credential) []string {
	left := ""
	right := ""
	if l != nil {
		left = t.leftDisplay(*l)
	}
	if r != nil {
		right = t.rightDisplay(*r)
	}
	return []string{left, right}
}

type postSort interface {
	postSort(l []CertCompareData)
}

type processErrors interface {
	getErrors() []error
}

// TPPGeneratedNameRegex specifies valid cert names
var TPPGeneratedNameRegex = regexp.MustCompile(`(.*)_[0-9]{2}[a-z]{3}[0-9]{2}_[A-Z]{2}[0-9]{2}`)

func removeTPPUploadSuffix(input string) string {
	return TPPGeneratedNameRegex.ReplaceAllString(input, "${1}")
}

func extractLastSegment(input string) string {
	split := strings.Split(input, "/")
	return split[len(split)-1]
}

func vaultTransform(input string) string {
	input = extractLastSegment(input)
	return removeTPPUploadSuffix(input)
}

func max(x, y int) int {
	if x < y {
		return y
	}
	return x
}

type prettyPrinter interface {
	headers() []string
	values(l *certificate.CertificateInfo, r *vault.Credential) []string
}

func printCertsPretty(ct ComparisonStrategy, data []CertCompareData) {
	pp, ok := ct.(prettyPrinter)
	if !ok {
		return
	}

	header2 := ""
	headers := pp.headers()
	header0 := headers[0]
	header1 := headers[1]
	if len(headers) > 2 {
		header2 = headers[2]
	}

	leftLongest := 0
	rightLongest := 0
	auxLongest := 0
	for _, d := range data {
		values := pp.values(d.Left, d.Right)
		left := values[0]
		right := values[1]
		if len(headers) > 2 {
			auxLongest = max(auxLongest, len(values[2]))
		}
		leftLongest = max(leftLongest, len(left))
		rightLongest = max(rightLongest, len(right))
	}

	header := ""
	if len(headers) > 2 {
		header = fmt.Sprintf("%s%s | %s | %s\n", output.Cyan, output.CenteredString(header0, leftLongest), output.CenteredString(header1, rightLongest), output.CenteredString(header2, auxLongest))
	} else {
		header = fmt.Sprintf("%s%s | %s\n", output.Cyan, output.CenteredString(header0, leftLongest), output.CenteredString(header1, rightLongest))
	}
	output.Print("%s", header)
	output.Print("%s\n", strings.Repeat("-", leftLongest+rightLongest+auxLongest+3*(len(headers)-1)))

	for _, d := range data {
		values := pp.values(d.Left, d.Right)
		left := values[0]
		right := values[1]
		leftColor := output.Red
		rightColor := output.Red
		if left != "" && right != "" {
			leftColor = output.Green
			rightColor = output.Green
		}

		if len(headers) > 2 {
			output.Print("%s%[2]*s %s| %s%[6]*s %s| %[9]*s\n", leftColor, -leftLongest, left, output.Cyan, rightColor, -rightLongest, right, output.Cyan, auxLongest, values[2])
		} else {
			output.Print("%s%[2]*s %s| %s%[6]*s\n", leftColor, -leftLongest, left, output.Cyan, rightColor, -rightLongest, right)
		}
	}
}
