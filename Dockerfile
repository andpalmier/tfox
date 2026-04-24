FROM alpine:3.23
RUN apk add --no-cache ca-certificates && \
    adduser -D -g '' appuser
COPY tfox /tfox
USER appuser
ENTRYPOINT ["/tfox"]
