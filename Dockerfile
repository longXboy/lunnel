FROM golang:1.8-alpine

RUN apk add --update \
  ca-certificates \
  && rm -rf /var/cache/apk/*

copy . /go/src/github.com/longXboy/Lunnel

RUN go install github.com/longXboy/Lunnel/client

ENTRYPOINT ["client"]
CMD ["-c","./config.yml"]
