# Multi-stage build.
# Build context must be the repo root so the betterauth package is reachable.
#   docker compose -f examples/docker-compose.yml build
# (docker-compose.yml sets context: .. which is the repo root)

FROM golang:1.24-alpine AS builder

WORKDIR /workspace

# Disable go workspaces so the example module is built independently
# using only its own go.mod + the replace directive pointing to ../../packages/betterauth.
ENV GOWORK=off

# Copy the betterauth library (required by the replace directive in go.mod)
COPY packages/betterauth/ packages/betterauth/

# Copy the example backend module
COPY examples/backend/ examples/backend/

WORKDIR /workspace/examples/backend

# Download dependencies
RUN go mod download

# Build a static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /server .

# ---

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /server /server

EXPOSE 8080

CMD ["/server"]
