# Bakes the selected model into the image so the stack runs without internet access.
ARG OLLAMA_BASE_IMAGE=ollama/ollama:latest
FROM ${OLLAMA_BASE_IMAGE}

ARG OLLAMA_MODEL=gpt-oss:20b

# Start a temporary server, wait until it answers, pull the model, then stop it.
# Fails the build if the server never comes up or the pull fails.
RUN set -eu; \
    ollama serve >/tmp/ollama-build.log 2>&1 & pid=$!; \
    i=0; until ollama list >/dev/null 2>&1; do \
        i=$((i+1)); [ "$i" -le 60 ] || { cat /tmp/ollama-build.log; exit 1; }; sleep 1; \
    done; \
    ollama pull "${OLLAMA_MODEL}"; \
    ollama list; \
    kill "$pid"; wait "$pid" 2>/dev/null || true; \
    rm -f /tmp/ollama-build.log
