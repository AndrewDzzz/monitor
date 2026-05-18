# ModelFP runtime auditing container.
# Build from repository root:
#   docker build -f docker/Dockerfile -t modelfp:latest .
# Optional ML deps:
#   docker build -f docker/Dockerfile --build-arg INSTALL_ML_DEPS=true -t modelfp:ml .

FROM python:3.11-slim

ARG INSTALL_ML_DEPS=false

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    MODELFP_HOME=/workspace/ModelFP_skill

RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    git \
    curl \
    file \
    jq \
    ca-certificates \
    libmagic1 \
  && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip \
  && python -m pip install modelscan huggingface_hub pyyaml jsonschema python-magic h5py \
  && if [ "$INSTALL_ML_DEPS" = "true" ]; then \
       python -m pip install torch --index-url https://download.pytorch.org/whl/cpu && \
       python -m pip install transformers safetensors accelerate sentencepiece protobuf tiktoken; \
     fi

WORKDIR /workspace
COPY . /workspace/ModelFP_skill

RUN mkdir -p /workspace/models /workspace/target /workspace/out /workspace/tmp /workspace/metadata \
  && chmod -R a+rX /workspace/ModelFP_skill \
  && useradd -m -u 1000 modelrunner \
  && chown -R modelrunner:modelrunner /workspace/out /workspace/tmp

USER modelrunner

ENTRYPOINT ["python", "/workspace/ModelFP_skill/code/modelfp_docker_runner.py"]
CMD ["--help"]
