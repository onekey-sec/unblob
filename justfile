builder_image_prefix := "ghcr.io/unblob/unblob-builder"

wheel target: (_build_container target) (_build_in_container target)

_build_container target:
    #! /usr/bin/env bash
    set -xeuo pipefail
    dockerfile=Dockerfile.build.{{ target }}
    cache_tag=$(< $dockerfile openssl sha256 -binary |  openssl sha256 -r | cut -d " " -f 1)
    image={{ builder_image_prefix }}-{{ target }}
    if ! docker pull $image:$cache_tag; then
        docker build -t $image:$cache_tag - < $dockerfile
    fi
    docker tag $image:$cache_tag $image:latest

_build_in_container target:
    docker run \
        -v $PWD:/usr/src/unblob \
        -v $HOME/.cargo/registry:/root/.cargo/registry \
        {{ builder_image_prefix }}-{{ target }}
