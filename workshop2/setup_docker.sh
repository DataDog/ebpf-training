#! /bin/bash

ROOT_DIR=$(dirname $(dirname $(realpath "${0}")))
docker run --privileged --net=host -v ${ROOT_DIR}:/src -w /src/workshop2 \
  -v /sys:/sys -v /lib:/lib -v /usr/src:/usr/src -it --rm gcr.io/seekret/ebpf-training-setup:latest
