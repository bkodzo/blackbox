FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/blackbox ./cmd/blackbox

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/blackbox /usr/local/bin/blackbox
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["blackbox"]
