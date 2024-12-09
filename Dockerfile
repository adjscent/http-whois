# Use the official Golang image to create a build artifact.
FROM golang:1.21 AS builder

# Create and change to the app directory.
WORKDIR /app

# Retrieve application dependencies.
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Copy local code to the container image.
COPY . ./

# Build the binary.
RUN CGO_ENABLED=0 go build -v -o server ./cmd/server

# Use a Docker multi-stage build to create a lean production image.
FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary to the production image from the builder stage.
COPY --from=builder /app/server .

# Run the web service on container startup.
CMD ["./server"]
