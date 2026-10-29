# Runtime image: the judge daemon plus every supported language toolchain.
# Needs --privileged (or at least CAP_SYS_ADMIN, a writable cgroup v2 and unconfined
# seccomp/apparmor) because it builds namespaces, mounts and cgroups for each submission.
FROM golang:bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/sandboxd ./cmd/sandboxd

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 gcc g++ libc6-dev nodejs default-jdk-headless ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/sandboxd /usr/local/bin/sandboxd
EXPOSE 8080
ENTRYPOINT ["sandboxd"]
