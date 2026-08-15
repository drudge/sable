FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETPLATFORM
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="Sable" \
      org.opencontainers.image.description="Modern, high-performance DNS server" \
      org.opencontainers.image.source="https://github.com/drudge/sable" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

COPY --chown=nonroot:nonroot ${TARGETPLATFORM}/sable /usr/local/bin/sable
COPY --chown=nonroot:nonroot docker/data/ /data/

WORKDIR /data
VOLUME ["/data"]

# DNS is deliberately unprivileged inside the container. Publish it as host
# port 53 with -p 53:8053/tcp -p 53:8053/udp.
EXPOSE 8053/tcp 8053/udp 5380/tcp 5443/tcp 853/tcp 443/tcp

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/sable"]
CMD ["serve", "--config", "/data/sable.toml"]
