#!/bin/sh
# Nyx repro — pin-fetch the toolchain image used by this bundle.
# Run this once on a fresh machine before `reproduce.sh --docker`.
set -e
IMAGE="python:3.11-slim@sha256:9a7765b36773a37061455b332f18e265e7f58f6fea9c419a550d2a8b0e9db834"
if ! command -v docker >/dev/null 2>&1; then
echo 'error: docker not installed' >&2; exit 2
fi
if ! docker info >/dev/null 2>&1; then
echo 'error: docker daemon not reachable' >&2; exit 2
fi
docker pull "$IMAGE"
