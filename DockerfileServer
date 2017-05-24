FROM golang:1.8.2-alpine

RUN apk add --update \
  ca-certificates \
  && rm -rf /var/cache/apk/*

copy . /go/src/github.com/longXboy/lunnel

RUN go install github.com/longXboy/lunnel/cmd/lunnelSer

ENTRYPOINT ["lunnelSer"]
CMD ["-c","./config.yml"]
