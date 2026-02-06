module github.com/jonwraymond/toolops-integrations

go 1.25.6

require (
	github.com/bitwarden/sdk-go v1.0.2
	github.com/jonwraymond/toolops v0.1.5
)

// Local development.
replace github.com/jonwraymond/toolops => ../toolops
