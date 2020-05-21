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

// +build integration

package main

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateVault(t *testing.T) {
	os.Args = []string{
		"noop", "create",
		"-name", "dev",
		"-cn", "dev.local",
		"-vault",
	}

	runCmd("create vault->venafi", t)
}

func TestRevokeVault(t *testing.T) {
	os.Args = []string{
		"noop", "revoke",
		"-name", "dev",
		"-vault",
	}

	runCmd("revoke vault->venafi", t)

	teardown()
}

func TestCreateVenafi(t *testing.T) {
	os.Args = []string{
		"noop", "create",
		"-name", "dev",
		"-cn", "dev.local",
	}

	runCmd("create venafi->vault", t)

	teardown()
}

func TestRevokeVenafi(t *testing.T) {
	os.Args = []string{
		"noop", "revoke",
		"-name", "dev",
	}

	runCmd("revoke venafi->vault", t)

	teardown()
}

func TestLoginUserpass(t *testing.T) {
	os.Args = []string{
		"noop", "login",
		"-method", "userpass",
		"-username", "dev",
		"-password", "dev9sk",
	}

	runCmd("login userpass", t)

	teardown()
}

func TestLoginCert(t *testing.T) {
	os.Args = []string{
		"noop", "login",
		"-method", "cert",
		"-certificate", "dev",
	}

	runCmd("login cert", t)

	teardown()
}

func runCmd(name string, t *testing.T) {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	cmd, err := parseCommand()
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Nil(t, err, "It should parse %s command", name)

	err = cmd.execute()
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Nil(t, err, "It should execute %s command", name)
}

func teardown() {
	os.Args = []string{}
}
