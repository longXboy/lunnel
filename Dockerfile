FROM golang:1.8-alpine

RUN apk add --update \
  ca-certificates \
  && rm -rf /var/cache/apk/*

copy . /go/src/Lunnel

RUN go install Lunnel/client

ENTRYPOINT ["client"]
CMD ["-c","./config.yml"]
