#!/bin/bash -ex

export DEBIFY_IMAGE='registry.tld/conjurinc/debify:1.11.4.0-04381b7'

docker run --rm $DEBIFY_IMAGE config script > docker-debify
chmod +x docker-debify

# Pulling private image explicitly and manually to local repository
# We don't pass registry credentials to debify, remove this when registry.tld/ruby-fips-base-image-phusion:1.0.0 become public.
docker pull registry.tld/ruby-fips-base-image-phusion:1.0.0

./docker-debify package \
  --dockerfile=Dockerfile.fpm \
  possum \
  -- \
  --depends tzdata
