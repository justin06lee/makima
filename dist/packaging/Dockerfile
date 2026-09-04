# makima in a container.
#
# Worth being clear about what this is and is not for. A container is the right
# home for `makima-relay` and `makima-server` — both are ordinary network
# services with no interest in the host's network stack, and both are things
# you want running somewhere permanently.
#
# `makimad` is a different matter: it creates a TUN device and edits a routing
# table, so it needs --cap-add=NET_ADMIN --device=/dev/net/tun and it
# reconfigures the *container's* network, not the host's. That is occasionally
# what somebody wants and is usually a misunderstanding, so it is not the
# default command.
FROM golang:1.25-alpine AS build

WORKDIR /src

# Dependencies first, so a source-only change does not re-download the module
# graph on every build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/ ./cmd/...

# Distroless-by-hand: the binaries are static, so the image needs nothing but
# certificates — the SSH server's github: key source is the one thing here that
# makes an outbound TLS connection.
FROM alpine:3.20

RUN apk add --no-cache ca-certificates && adduser -D -u 10001 makima

COPY --from=build /out/makima        /usr/local/bin/makima
COPY --from=build /out/makimad       /usr/local/bin/makimad
COPY --from=build /out/makima-server /usr/local/bin/makima-server
COPY --from=build /out/makima-relay  /usr/local/bin/makima-relay

# The relay is the one that makes sense unprivileged, and the one most people
# running this image actually want: a fixed point two NATed machines can meet
# at. 3478 is the STUN port, chosen because traffic to it is unremarkable.
USER makima
EXPOSE 3478/tcp
VOLUME /var/lib/makima

ENTRYPOINT ["makima-relay"]
