# syntax=docker/dockerfile:1

# Stage 1: Build binary
FROM golang:alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o panel ./cmd/panel

# Stage 2: Production image
FROM alpine:latest
WORKDIR /app

# Install openssh-client and ca-certificates
RUN apk add --no-cache openssh-client ca-certificates tzdata

# Create data directory for SQLite database
RUN mkdir -p /data
ENV DB_PATH=/data/panel.db
ENV PORT=8000

COPY --from=builder /app/panel .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
COPY --from=builder /app/translations ./translations

EXPOSE 8000

CMD ["./panel"]
