# Build stage
FROM golang:1.22-bookworm AS builder

# Install MuPDF dependencies
RUN apt-get update && apt-get install -y \
    libmupdf-dev \
    pkg-config \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /server ./cmd/server/

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libmupdf-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /server /app/server

EXPOSE 8080

ENTRYPOINT ["/app/server"]
