module example.com/replace-no-version

go 1.21

require github.com/old/module v1.5.0

replace github.com/old/module => github.com/new/module v1.2.3
