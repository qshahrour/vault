FROM alpine:latest
WORKDIR /root/
COPY vaultbot .
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
ENTRYPOINT ["./vaultbot"]
