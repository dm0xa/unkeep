# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY backend ./backend
COPY frontend ./frontend
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor \
    -trimpath -ldflags="-s -w -X main.buildVersion=${VERSION}" \
    -o /out/unkeep ./backend

FROM scratch
COPY --from=build /out/unkeep /unkeep
USER 65532:65532
EXPOSE 8080
ENV HOST=0.0.0.0 \
    PORT=8080 \
    GOMEMLIMIT=400MiB
STOPSIGNAL SIGTERM
ENTRYPOINT ["/unkeep"]
