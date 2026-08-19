# LabMITM production image: ghcr.io/hilather/labmitm
#
# Multi-stage, static binary, numeric non-root UID, no shell.
# Run with a read-only root filesystem, cap_drop ALL, and no-new-privileges.
# Container ports stay 8888 (proxy) and 8088 (management). Healthcheck is HTTP
# ready via the copied binary. No Node stage — UI-001 embeds dist/ on the host.

FROM golang:1.26.6-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build -trimpath \
	-ldflags="-s -w \
	-X github.com/hilather/go-lab-mitmproxy/internal/buildinfo.version=${VERSION} \
	-X github.com/hilather/go-lab-mitmproxy/internal/buildinfo.commit=${COMMIT} \
	-X github.com/hilather/go-lab-mitmproxy/internal/buildinfo.buildTime=${BUILD_TIME}" \
	-o /out/labmitm ./cmd/labmitm \
	&& printf 'labmitm:x:65532:65532:labmitm:/:/sbin/nologin\n' > /out/passwd \
	&& printf 'labmitm:x:65532:\n' > /out/group \
	&& cp /etc/ssl/certs/ca-certificates.crt /out/ca-certificates.crt \
	&& cp LICENSE /out/LICENSE

FROM scratch

LABEL org.opencontainers.image.title="labmitm" \
	org.opencontainers.image.description="Laboratory HTTP(S) intercepting proxy" \
	org.opencontainers.image.source="https://github.com/hilather/go-lab-mitmproxy" \
	org.opencontainers.image.url="https://github.com/hilather/go-lab-mitmproxy" \
	org.opencontainers.image.licenses="Apache-2.0" \
	org.opencontainers.image.vendor="hilather" \
	org.opencontainers.image.documentation="https://github.com/hilather/go-lab-mitmproxy/blob/main/docs/13-deployment.md"

COPY --from=build /out/passwd /etc/passwd
COPY --from=build /out/group /etc/group
COPY --from=build /out/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/labmitm /labmitm
COPY --from=build /out/LICENSE /LICENSE

USER 65532:65532
EXPOSE 8888/tcp 8088/tcp
WORKDIR /

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
	CMD ["/labmitm", "healthcheck", "--url=http://127.0.0.1:8088/v1/health/ready"]

ENTRYPOINT ["/labmitm"]
# serve --management-listen defaults to off (proxy-only). The image must bind
# management so HEALTHCHECK and authenticated /v1 work from the published 8088.
CMD ["serve", "--config=/etc/labmitm/config.yaml", "--management-listen=:8088"]
