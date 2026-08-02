# Docker Compose for LogonTracer with Offline Local LLM

This compose profile starts LogonTracer, Neo4j, and Ollama in one Docker network.
LogonTracer is configured to use Ollama through the OpenAI-compatible endpoint at `http://ollama:11434/v1`.
The images are built while internet access is available, then used in a closed network without runtime access to GitHub, CDNs, OpenAI, or Ollama model registries.

## Online Build

```shell
cd docker-compose-localllm
cp .env.example .env
docker compose build
```

The build performs the online-only work:

- downloads Python, OS, and Rust build dependencies
- downloads browser JS/CSS assets into `static/vendor`
- clones Sigma rules into the LogonTracer image
- pulls the configured Ollama model into the Ollama image

Start once in the online environment if you also want Docker to pull the Neo4j image before exporting:

```shell
docker compose up -d
docker compose exec ollama ollama list
docker compose down
```

## Offline Use

After the images have been built or loaded into the closed network host, start without rebuilding:

```shell
docker compose up -d --no-build
```

Open LogonTracer at:

```text
http://localhost:8080
```

The LogonTracer container runs with `LOGONTRACER_OFFLINE=true`, so Sigma scans use the bundled `sigma/` directory and the web UI uses only local `/static/vendor` assets.

## Export Images

To move the built images to a closed network without a registry:

```shell
docker save \
  logontracer:localllm-offline \
  logontracer-ollama:llama3.1-8b \
  neo4j:5.26.19-enterprise \
  -o logontracer-localllm-offline-images.tar
```

On the closed network host:

```shell
docker load -i logontracer-localllm-offline-images.tar
cd docker-compose-localllm
docker compose up -d --no-build
```

## NVIDIA GPU

On Linux hosts with the NVIDIA Container Toolkit:

```shell
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d
```

## Model Settings

Edit `.env` before building to change the model or Ollama runtime defaults:

```shell
OLLAMA_BASE_IMAGE=ollama/ollama:latest
OLLAMA_MODEL=llama3.1:8b
OLLAMA_IMAGE_TAG=llama3.1-8b
OLLAMA_CONTEXT_LENGTH=16384
OLLAMA_KEEP_ALIVE=30m
LOGONTRACER_MAX_COMPLETION_TOKENS=4096
LOGONTRACER_FINAL_REPORT_MAX_COMPLETION_TOKENS=4096
LOGONTRACER_TEMPERATURE=0
LOGONTRACER_AGENT_MAX_ITERATIONS=6
LOGONTRACER_MAX_UPLOAD_MB=2048
FETCH_SIGMA_RULES=true
SIGMA_REPO=https://github.com/SigmaHQ/sigma.git
```

When `OLLAMA_MODEL` changes, also change `OLLAMA_IMAGE_TAG` to a Docker-safe tag such as `llama3.2-3b`.
For larger investigations, `OLLAMA_CONTEXT_LENGTH=32768` or higher can be used when the selected model and hardware can support it.
For local LLM analysis stability, keep `LOGONTRACER_MAX_COMPLETION_TOKENS` modest, typically `2048` or `4096`.
Use `LOGONTRACER_FINAL_REPORT_MAX_COMPLETION_TOKENS` to give the final JSON report more room without increasing every intermediate step.
Increase `LOGONTRACER_MAX_UPLOAD_MB` if you need to import very large EVTX files.
