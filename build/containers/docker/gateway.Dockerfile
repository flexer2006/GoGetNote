FROM golang:1.24.2-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o gateway-service ./cmd/gateway

FROM alpine:3.21

WORKDIR /app

RUN apk --no-cache add ca-certificates tzdata netcat-openbsd

COPY --from=builder /app/gateway-service .

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD nc -z localhost ${GATEWAY_HTTP_PORT:-8080} || exit 1

ENTRYPOINT ["./gateway-service"]