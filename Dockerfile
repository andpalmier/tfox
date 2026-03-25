FROM alpine:3.19
RUN apk add --no-cache ca-certificates && \
    adduser -D -g '' appuser
COPY tfox /tfox
USER appuser
ENTRYPOINT ["/tfox"]
