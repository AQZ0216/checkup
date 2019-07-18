FROM golang:1.12.4-alpine3.9 as build

ENV PATH=/root/go/bin:$PATH

RUN apk add --no-cache git make gcc musl-dev linux-headers ca-certificates openssh-client
# setup for accessing private bitbucket repo
COPY id_rsa  /root/.ssh/
RUN git config --global url."git@bitbucket.org:".insteadOf "https://bitbucket.org/" && \
	echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config

# install glide
RUN go get github.com/Masterminds/glide

RUN mkdir -p /go/src/github.com/sourcegraph/checkup && \
        cd /go/src/github.com/sourcegraph/ && \
	git clone git@bitbucket.org:cybavo/healthcheck.git checkup && \
	cd checkup && \
        glide install && \
        go build -ldflags "-s -w" cmd/checkup/main.go

# Build stage for compiled artifact
FROM alpine:3.9

RUN apk add --no-cache ca-certificates

COPY --from=build /go/src/github.com/sourcegraph/checkup/main /main

ENTRYPOINT ["/main"]
