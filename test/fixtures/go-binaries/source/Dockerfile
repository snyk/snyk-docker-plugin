ARG GO_IMAGE_TAG

FROM golang:$GO_IMAGE_TAG
ARG GO_VERSION

WORKDIR /app
COPY go.mod go.sum main.go ./

# as we build with a huge difference between versions, the go mod file sometimes needs to be tidied up.
RUN go mod tidy 

RUN mkdir /app/out

# build the normal binary, with CGo disabled.
RUN env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ./out/"$GO_VERSION"_normal .

# for latest, we also want to build a normal but stripped binary.
RUN if [ "$GO_VERSION" = "latest" ]; then \
    env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' -o ./out/"$GO_VERSION"_stripped .; \
fi;

# required for CGo
RUN apk add musl-dev git gcc 
COPY main.cgo ./main.go

# build the Cgo binary stripped and trimmed.
RUN env GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -trimpath -ldflags='-s -w' -o ./out/"$GO_VERSION"_cgo_trimmed_stripped .

# and build a pure CGo binary for latest as well.
RUN if [ "$GO_VERSION" = "latest" ]; then \
    env GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o ./out/"$GO_VERSION"_cgo .; \
fi;

