package bws

import sdk "github.com/bitwarden/sdk-go"

// Narrow interfaces so unit tests can provide fakes without implementing the entire SDK surface.

type bwsClient interface {
	Projects() sdk.ProjectsInterface
	Secrets() sdk.SecretsInterface
	Close()
}

