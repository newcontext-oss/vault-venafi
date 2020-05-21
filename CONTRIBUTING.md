# Contributing

This document describes how to contribute to this project.
Proposals for changes to this document are welcome.

## Table of Contents

[Code of Conduct](#code-of-conduct)

[Asking Questions](#asking-questions)

[Project Technologies](#project-technologies)

## Code of Conduct

Contributors to this project are expected to adhere to the
[Code of Conduct](CODE_OF_CONDUCT.md). Any unacceptable conduct
should be reported to opensource@newcontext.com.

## Questions

Questions about the project may be posed on the
[GitHub issue tracker][github-issue-tracker].

## Project Technologies

Familiarity with the following technologies is important in
understanding the design and behaviour of this project.

- [Go][go]
- [VenaVenafi Trust Protection Platform][venafi]
- [Vault][vault]

## Reporting Bugs

Bugs must be reported on the
[GitHub issue tracker](github-issue-tracker). Any information that will assist in the maintainers reproducing the bug should be included.

## Suggesting Changes

Changes should be suggested on the
[GitHub issue tracker](github-issue-tracker). Submitting a pull request with an implementation of the changes is also encouraged but not required.

## Developing

The development workflow for this project follows
[standard GitHub workflow](fork-a-repo).

### Unit Testing

[Golang testing package][gotest] is used as the unit testing framework.

The following command will execute the unit tests.

> Executing unit tests with Go's testing package

```sh
go test -v ./...
```

The json files under [testdata](testdata) contain supporting json files for testing.

### Continuously Integrating and Continuously Deploying
GitHub Actions are used to provide continuous integration and continuous deployment functionality for this app.

The workflows are configured at .github/workflows/

Linting, static analysis via [Staticcheck][staticcheck], and unit tests will be executed for each commit to a branch as well as all pull requests.

If a commit to the master branch has a tag starting with a v, then the job will attempt to build the app and deploy it as a [release][release].

<!-- Markdown links and image definitions -->
[vault]: https://www.vaultproject.io/
[fork-a-repo]: https://help.github.com/articles/fork-a-repo/
[github-issue-tracker]: https://github.com/newcontext-oss/vault-venafi/issues
[go]: https://golang.org/
[gotest]: https://golang.org/pkg/testing
[release]: https://github.com/newcontext-oss/vault-venafi/releases
[staticcheck]: https://staticcheck.io/
[testdata]: https://github.com/newcontext-oss/vault-venafi/tree/master/testdata
[venafi]: https://venafi.com
