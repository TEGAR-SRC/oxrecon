# Multi-stage Docker build for oxrecon
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /oxrecon main.go

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /root/

COPY --from=builder /oxrecon /usr/local/bin/oxrecon
COPY configs/default.yaml /etc/oxrecon/config.yaml

EXPOSE 8080

ENTRYPOINT ["oxrecon"]
CMD ["--help"]
