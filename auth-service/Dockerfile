# Stage 1: Builder
FROM golang:1.25-alpine AS builder

# Install protoc binary
RUN apk add --no-cache protobuf

# Install Go plugins for protoc
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

WORKDIR /app

# Copy proto files
COPY proto ./proto

# Generate .pb.go files
RUN mkdir -p pb/userpb && \
    protoc \
    --go_out=pb/userpb \
    --go-grpc_out=pb/userpb \
    --go_opt=paths=source_relative \
    --go-grpc_opt=paths=source_relative \
    proto/user.proto

# Copy go.mod and go.sum first to leverage caching
COPY go.mod go.sum ./
RUN go mod download

# Copy all source code (including generated pb)
COPY . .

# Build the binary
RUN go build -o auth-service main.go

# Stage 2: Minimal runtime image
FROM alpine:3.22
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/auth-service .

# Expose port (adjust if needed)
EXPOSE 8080

# Command to run
CMD ["./auth-service"]
