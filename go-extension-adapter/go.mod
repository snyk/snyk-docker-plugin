module github.com/snyk/snyk-docker-plugin/extension-adapter

go 1.22

require (
	github.com/snyk/go-application-framework v0.0.0-20260506111235-cca3157b9435
	github.com/snyk/snyk-docker-plugin v0.0.0-00010101000000-000000000000
)

// Replace with the local workspace path when using in cliv2.
// In cliv2/go.mod add:
//   replace github.com/snyk/snyk-docker-plugin => ../../snyk-docker-plugin/go
//   replace github.com/snyk/snyk-docker-plugin/extension-adapter => ../../snyk-docker-plugin/go-extension-adapter
replace github.com/snyk/snyk-docker-plugin => ../go
