FROM golang:1-alpine AS build
RUN apk add --no-cache upx
WORKDIR $GOPATH/src/github.com/gstolarz/drone-portainer
COPY . .
RUN CGO_ENABLED=0 go install -ldflags="-s -w" ./... \
  && upx --ultra-brute $GOPATH/bin/drone-portainer

FROM plugins/base:multiarch
LABEL maintainer="grzegorz.stolarz@gmail.com" \
  org.label-schema.name="Drone Portainer Plugin" \
  org.label-schema.vendor="Grzegorz Stolarz" \
  org.label-schema.schema-version="1.0"
COPY --from=build /go/bin/drone-portainer /bin/drone-portainer
ENTRYPOINT ["/bin/drone-portainer"]
