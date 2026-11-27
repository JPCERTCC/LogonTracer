FROM python:3.13.7-slim

RUN set -ex \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        gcc \
        g++ \
        git \
        libssl-dev \
        make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/src

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /usr/local/src/LogonTracer

COPY requirements.txt ./
RUN python -m pip install --upgrade pip \
    && pip install cython \
    && pip install numpy \
    && pip install scipy \
    && pip install statsmodels \
    && pip install -r requirements.txt

COPY config ./config
COPY intelligence ./intelligence
COPY static ./static
COPY templates ./templates
COPY images ./images
COPY model ./model
COPY es-index ./es-index
COPY sample ./sample
COPY sigma ./sigma
COPY sigma-custom ./sigma-custom
COPY logontracer.py detection.py README.md LICENSE.txt ./
COPY docker-compose/LogonTracer/build/fetch_vendor_assets.sh /usr/local/bin/fetch_vendor_assets.sh

ARG FETCH_SIGMA_RULES=false
ARG SIGMA_REPO=https://github.com/SigmaHQ/sigma.git

RUN sed -i 's/\r$//' /usr/local/bin/fetch_vendor_assets.sh \
    && chmod 755 /usr/local/bin/fetch_vendor_assets.sh \
    && /bin/sh /usr/local/bin/fetch_vendor_assets.sh /usr/local/src/LogonTracer/static/vendor \
    && if [ "${FETCH_SIGMA_RULES}" = "true" ]; then \
        rm -rf /usr/local/src/LogonTracer/sigma \
        && git clone --depth 1 "${SIGMA_REPO}" /usr/local/src/LogonTracer/sigma; \
    fi

# Run as an unprivileged user instead of root + world-writable (777) folders.
# The app writes .secret_key in its root folder, data.db in instance/, and logs/upload/cache/static/sigma below it.
RUN useradd --system --uid 10001 --home-dir /usr/local/src/LogonTracer --shell /usr/sbin/nologin logontracer \
    && mkdir -p logs/llm_interactions upload cache instance \
    && chown logontracer:logontracer /usr/local/src/LogonTracer \
    && chown -R logontracer:logontracer static logs upload cache instance sigma \
    && chmod 750 /usr/local/src/LogonTracer static logs upload cache instance

WORKDIR /usr/local/src

RUN echo "#!/bin/bash" > run.sh \
    && echo "sleep 60" >> run.sh \
    && echo "cd /usr/local/src/LogonTracer" >> run.sh \
    && echo "# Neo4j password comes from LOGONTRACER_NEO4J_PASSWORD (never on the command line)" >> run.sh \
    && echo "exec python logontracer.py -r -o 8080 -u neo4j -s \${LTHOSTNAME:-neo4j}" >> run.sh \
    && chmod 755 run.sh

EXPOSE 8080

USER logontracer

CMD ["/usr/local/src/run.sh"]
