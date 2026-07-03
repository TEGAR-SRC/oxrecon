# Multi-stage Docker build for WebTool
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /webtool main.go

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /root/

COPY --from=builder /webtool /usr/local/bin/webtool
COPY configs/default.yaml /etc/webtool/config.yaml

EXPOSE 8080

ENTRYPOINT ["webtool"]
CMD ["--help"]
