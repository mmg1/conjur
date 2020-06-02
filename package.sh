#!/bin/bash -ex
export DEBIFY_IMAGE='registry.tld/conjurinc/debify:1.11.4.12-c959595'

docker run --rm $DEBIFY_IMAGE config script > docker-debify
chmod +x docker-debify

# Pulling private image explicitly and manually to local repository
# We don't pass registry credentials to debify, remove this when registry.tld/ruby-fips-base-image-phusion:1.0.0
# become public. https://github.com/conjurinc/debify/blob/c959595858cd1244c461c63b7086204bf88b3042/lib/conjur/fpm/Dockerfile#L2
docker pull registry.tld/ruby-fips-base-image-phusion:1.0.0

./docker-debify package \
  --dockerfile=Dockerfile.fpm \
  possum \
  -- \
  --depends tzdata
