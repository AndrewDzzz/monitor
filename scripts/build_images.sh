#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL_DIR="$ROOT/skills/codex/modelfp"

docker build -f "$SKILL_DIR/docker/Dockerfile" -t "${MODELFP_IMAGE:-modelfp:latest}" "$SKILL_DIR"
docker build -f "$SKILL_DIR/docker/Dockerfile" --build-arg INSTALL_ML_DEPS=true -t "${MODELFP_ML_IMAGE:-modelfp:ml}" "$SKILL_DIR"

docker image inspect -f 'built {{.RepoTags}} {{.Id}}' "${MODELFP_IMAGE:-modelfp:latest}" "${MODELFP_ML_IMAGE:-modelfp:ml}"
