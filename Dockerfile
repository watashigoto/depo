FROM golang:1.18

ENV GO111MODULE=auto

RUN mkdir /go/depo
ADD . /go/depo
WORKDIR /go/depo
RUN go mod download
RUN go build -o main .
CMD ["/go/depo/main"]
