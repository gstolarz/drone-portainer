#!/bin/sh
docker run --rm -u $(id -u):$(id -g) -v $PWD:/workdir \
    openapitools/openapi-generator-cli generate \
    -i /workdir/swagger/portainer-api-v1.24.1.yaml \
    -g go \
    -o /workdir/lib/portainer \
    --additional-properties=packageName=portainer
patch -p0 < portainer.diff
