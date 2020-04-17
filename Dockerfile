FROM golang:alpine AS build
RUN apk add --no-cache git mercurial \
    && go get gopkg.in/square/go-jose.v2 \
    && apk del git mercurial
RUN apk add --update alpine-sdk
WORKDIR /go/src/github.com/cloudflare/cfssl
COPY . .
ENV GOPATH /go/
RUN make -j4

FROM alpine
COPY --from=build /go/src/github.com/cloudflare/cfssl/bin /app/bin
COPY --from=build /go/src/github.com/cloudflare/cfssl/myscripts /app/myscripts
COPY --from=build /go/src/github.com/cloudflare/cfssl/myconfig /app/myconfig
WORKDIR /app/myconfig/
ENTRYPOINT ["../myscripts/run_multirootca.sh"]
