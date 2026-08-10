module example.com/replace-block

go 1.21

require (
	github.com/old/module v1.0.0
	github.com/local/drop v1.0.0
	github.com/another/old v2.0.0
)

replace (
	github.com/old/module v1.0.0 => github.com/new/module v2.0.0
	github.com/local/drop v1.0.0 => ../local
)
