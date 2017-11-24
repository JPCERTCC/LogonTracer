# docker-LogonTracer
  Dockerfile for LogonTracer.  
  The Docker image is the following URL.  
  https://hub.docker.com/r/jpcertcc/docker-logontracer/

## Usage
  ```shell
  $ docker run \
    --detach \
    --publish=7474:7474 --publish=7687:7687  --publish=8080:8080 \
    -e LTHOSTNAME=[IP Address] \
    jpcertcc/docker-logontracer
  ```
