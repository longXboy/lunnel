FROM golang:1.8

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates vim \
	&& apt-get autoremove -y && apt-get clean

copy . /go/src/Lunnel

RUN go install Lunnel/server
RUN go install Lunnel/cli

CMD ["cli"]