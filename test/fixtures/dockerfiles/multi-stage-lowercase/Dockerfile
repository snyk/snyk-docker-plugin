from golang:1.7.3 as builder
workdir /go/src/github.com/alexellis/href-counter/
run go get -d -v golang.org/x/net/html
copy app.go .
run cgo_enabled=0 goos=linux go build -a -installsuffix cgo -o app .

from alpine:latest as base
run apk --no-cache add ca-certificates
workdir /root/
copy --from=builder /go/src/github.com/alexellis/href-counter/app .
cmd ["./app"]

from base as extended

from extended
