FROM alpine:latest
RUN apk add --no-cache ca-certificates && \
    adduser -D -g '' appuser
COPY tfox /tfox
USER appuser
ENTRYPOINT ["/tfox"]
