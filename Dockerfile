# syntax=docker/dockerfile:1
# get-sybers/godaemonhunter — the Linux daemon-parser matrix as one static
# binary (every parser a sub-tool; hunt is the layered all-streams run).
# Built from the REPO ROOT: the image copies the sibling pinfo/ module.

ARG GO_VERSION=1.25
ARG TOOL_VERSION=0.3.0
ARG GODFIR_REVISION=unknown
ARG GODFIR_RELEASE=dev

FROM golang:${GO_VERSION}-alpine AS build
ARG TOOL_VERSION
WORKDIR /src
COPY pinfo/ pinfo/
COPY godaemonhunter/go.mod godaemonhunter/go.sum godaemonhunter/
WORKDIR /src/godaemonhunter
RUN go mod download
WORKDIR /src
COPY godaemonhunter/ godaemonhunter/
WORKDIR /src/godaemonhunter
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${TOOL_VERSION}" -o /godaemonhunter .
# build-stage sanity gate
RUN /godaemonhunter --version

# gomount: CGO-free static reader of the disk image (its go.mod pins the Go
# it needs; the toolchain downloads it when the base is older)
FROM golang:alpine AS gomount-build
ARG TOOL_VERSION
ENV GOTOOLCHAIN=auto
WORKDIR /src/gomount
COPY gomount/go.mod gomount/go.sum ./
RUN go mod download
COPY gomount/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${TOOL_VERSION}" -o /out/gomount .

FROM scratch
COPY --from=build /godaemonhunter /godaemonhunter
COPY --from=gomount-build /out/gomount /usr/local/bin/gomount
COPY <<HARDENED /etc/dfir-hardened
schema=1
tool=godaemonhunter
user=dfir uid=2000 gid=2000
static_binary=true
shell=false python=false pkg_mgr=false
HARDENED
ARG DFIR_UID=2000
ARG DFIR_GID=2000
ARG TOOL_VERSION
ARG GODFIR_REVISION
ARG GODFIR_RELEASE
ENV HOME=/tmp XDG_CACHE_HOME=/tmp/.cache
USER ${DFIR_UID}:${DFIR_GID}
ENTRYPOINT ["/godaemonhunter"]
LABEL org.opencontainers.image.title="get-sybers/godaemonhunter" \
      org.opencontainers.image.description="The Linux matrix as one structured binary: every daemon parser embedded as a sub-tool, plus hunt — the layered run that builds the Layer-1 knowledge store and runs every daemon parser enriched by it. Env-driven multi-tool entrypoint on the shared pinfo module; FROM scratch, runs as uid 2000." \
      org.opencontainers.image.source="https://github.com/Get-Sybers/GoDFIR-toolz" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.revision="${GODFIR_REVISION}" \
      com.get-sybers.tool="godaemonhunter" \
      com.get-sybers.hardened="true" \
      com.get-sybers.contract="1" \
      com.get-sybers.godfir-release="${GODFIR_RELEASE}"
