# Vault-Venafi

Commonly manage certificates in both Venafi and Vault.

[![New Context](https://img.shields.io/badge/awesome-for%20hire-orange?style=flat-square)](http://www.newcontext.com)

Vault-Venafi is a CLI tool (`vv`) that helps manage keys & certificates, also known as machine identities, located in Venafi Trust Protection Platform and Hashicorp Vault. This provides the user with a single, convenient interface to manage two separate systems with a few commands.

When creating machine identities in Venafi TPP and copying to Vault, the KV Secrets Engine is used. This is because the Vault PKI Secrets Engine does not allow certificates to be imported from external sources.

On the other hand, certificates created in Vault use the PKI Secrets Engine and are then copied to TPP. The Vault KV Secrets Engine is also used here to store additional metadata.

## Build Binary

```sh
go build -o vv
```

## Run Unit Tests

```sh
go test ./...
```

## Config File

Configuration is read at runtime from the `.vault-venafi.conf` file in calling user's home directory. Use the appropriate configuration file for your setup.

### Venafi Cloud
```
apikey: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
zone: zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz
connector_type: cloud
vault_token: token
vault_base_url: http://127.0.0.1:8200
vault_role: vault
vault_kv_path: secret/kv/path
vault_pki_path: secret/pki/path
log_level: status
```

### Venafi Platform
```
vcert_username: tppadmin
vcert_password: topsecret
vcert_zone: \Certificates
vcert_base_url: https://yourvenafiinstall.com/vedsdk/
vcert_access_token: WkDQ/zJsFOXzLEWQQ51mlw== (optional)
connector_type: tpp
vault_token: token
vault_base_url: http://127.0.0.1:8200
vault_role: vault
vault_kv_path: secret/kv/path
vault_pki_path: secret/pki/path
log_level: status
```

##### Direct Access Token Support
```
vcert_access_token: WkDQ/zJsFOXzLEWQQ51mlw== (bearer access token)
vcert_zone: \Certificates
vcert_base_url: https://yourvenafiinstall.com/vedsdk/
connector_type: tpp
vault_token: token
vault_base_url: http://127.0.0.1:8200
vault_role: vault
vault_kv_path: secret/kv/path
vault_pki_path: secret/pki/path
log_level: status
```

##### Legacy APIKey Support
```
vcert_username: tppadmin
vcert_password: topsecret
vcert_legacy_auth: true
vcert_zone: \Certificates
vcert_base_url: https://yourvenafiinstall.com/vedsdk/
connector_type: tpp
vault_token: token
vault_base_url: http://127.0.0.1:8200
vault_role: vault
vault_kv_path: secret/kv/path
vault_pki_path: secret/pki/path
log_level: status
```

```
Where:
vcert_username/vcert_password: will be credentials of the user to log into Venafi TPP
vcert_zone: policy path in Venafi TPP to store certificates, this path MUST pre-created
vcert_base_url: the URL to Venafi TPP
vcert_access_token: bearer token obtained from Venafi TPP, used for token-based authentication in v19.2+ (optional)
connector_type: Venafi tpp or cloud
vault_token: access token to be used for Vault
vault_base_url: the URL to the Vault instance
vault_kv_path: the path in Vault where the key-value pair Venafi certificates are stored
vault_pki_path: the path in Vault where the Vault certificates are stored
vault_role: the role to use in Vault when creating certificates
Log_level: STATUS, VERBOSE, INFO or ERROR
skip_tls_validation: true (when using self-signed certificates)
```

**NOTE**: The vcert_access_token is optional as the Vault-Venafi tool will obtain a token on the fly for the username if one is not specified.

Previous to Venafi Trust Protection Platform (TPP) v19.2 all authentication was handled via username/password with an API-Key. With TPP v19.2 token-based authentication was introduced and Venafi plans to deprecate the API-Key authentication method at the end of 2020. TPP v20.4 will be the last release that supports API-Key authentication.

### vault_kv_path

Path used to manage certificates when using Vault KV Secrets Engine.

### vault_pki_path

Path used to store additional metadata for certificates when using Vault PKI Secrets Engine.

This is required for managing certificates between TPP and Vault PKI. For example, Vault PKI stores certificates with a random serial number while TPP stores a human-friendly name. A map in Vault KV stores a mapping of the human-friendly name to the serial number.

### vault_role

Role used when creating certificates with Vault PKI Secrets Engine.

### vcert_legacy_auth

(Deprecated) Flag used when connecting to an older TPP service.

## Help Usage

Adding the `-h` or `-help` flag to command reveals the help associated with that command.

i.e.

```
Usage:
  vv [command]

Available commands:
  create   Generate a certificate and upload to Venafi
  revoke   Revoke a credential
  list     List certificates in each system
  login    Login to Vault with token, userpass or cert auth
```

## Commands

* login
* create
* revoke
* list

## Login

* Authenticates to vault and retrieves an access token
* TPP authentication happens with each command.

### UserPass Login

```
vv login -method "userpass" -username "foo" -password "bar"
```

### Cert Login

```
export VAULT_CLIENT_CERT=server.crt
export VAULT_CLIENT_KEY=server.key

vv login -method "cert" -certificate "foo"
```

### Save Token

Normally the access token is printed to stdout, but can be saved to the config file
by passing a "-save" flag.

```
vv login -method "userpass" -username "foo" -password "bar" -save
```

## Create

### Create from Venafi

Create a certificate in Venafi and upload to Vault using KV Secrets Engine.

```
vv create -cn "test.local" -name "test-local"
```

### Create from Vault

Create a certificate in Vault using PKI Secrets Engine and upload to Venafi.


```
vv create -cn "test.local" -name "test-local" -vault
```

Uses -vault flag.

## List

### List from Venafi

Lists certificates in Venafi and Vault KV Secrets Engine

```
vv list
```

This mode takes the provided thumbprint on the Venafi side and on the Vault side it lists and then pulls and computes the thumbprint for each credential because Vault does not provide the thumbprint.

### List from Vault

Lists certificates in Venafi and Vault PKI Secrets Engine

```
vv list -vault
```

## Revoke

### Revoke from Venafi

```
vv revoke -name "test-local"
```

Revokes a certificate in Venafi and deletes in Vault KV Secrets Engines.

### Revoke from Vault

```
vv revoke -name "test-local" -vault
```

Revokes a certificate in Venafi and Vault PKI Secrets Engines.


# Powered by New Context

[![New Context Logo](https://newcontext.com/wp-content/uploads/2018/02/New-Context-logo2.png)](http://www.newcontext.com)

Vault-Venafi is maintained and funded by New Context, which provides
"security first" automation to mission critical infrastructure.
Founded in 2013, we were doing DevSecOps before it became a buzzword. You can
[hire us](https://newcontext.com/contact-us/) to
improve your time-to-market, reduce risk, and boost your security/compliance posture.

We're always [looking to hire](https://newcontext.com/careers/) seasoned engineers,
with a mixed background across development, IT infrastructure, automation, and/or security.
