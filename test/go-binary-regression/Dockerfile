FROM golang:alpine
COPY . /app
WORKDIR /app
RUN unset GOPATH
RUN CGO_ENABLED=0 go build
CMD ["sh"]
