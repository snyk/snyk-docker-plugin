module example.com/malformed

go 1.21

require github.com/good/module v1.0.0

require (
	github.com/also/good v2.0.0
	STRAY_TOKEN_HERE
	github.com/block/good v3.0.0
