# setcap only writes an extended attribute, so this stage runs on the build
# platform for every target. The capability is permitted, not effective: with
# the effective bit a container run with cap_drop ALL couldn't start. The
# launcher raises it (cmd/sable/container_capabilities_linux.go). The binary is
# owned by nonroot here because a chown after setcap clears the capability. The
# base is pinned by digest because this stage writes the capability every
# release image depends on.
FROM --platform=$BUILDPLATFORM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS capabilities
ARG TARGETPLATFORM
RUN apk add --no-cache libcap-setcap
COPY ${TARGETPLATFORM}/sable /sable
RUN chown 65532:65532 /sable && setcap cap_net_bind_service=p /sable

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

COPY --from=capabilities /sable /usr/local/bin/sable
COPY --chown=nonroot:nonroot docker/data/ /data/

WORKDIR /data
VOLUME ["/data"]

# On a bridge, DNS stays unprivileged: publish it as host port 53 with
# -p 53:8053/tcp -p 53:8053/udp. With host networking (compose.dhcp.yaml),
# the file capability lets it bind port 53 and DHCP's port 67.
EXPOSE 8053/tcp 8053/udp 5380/tcp 5443/tcp 853/tcp 443/tcp

USER nonroot:nonroot
# The immutable launcher normally behaves exactly like the Sable command. When
# SABLE_WEB_UPDATES=true it can hand off to a newer, non-root executable stored
# in /data without exposing the Docker socket or any host privileges.
ENTRYPOINT ["/usr/local/bin/sable", "container"]
CMD ["serve", "--config", "/data/sable.toml"]
