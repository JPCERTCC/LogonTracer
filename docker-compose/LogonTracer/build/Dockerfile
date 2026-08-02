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
COPY logontracer.py README.md LICENSE.txt ./
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

RUN mkdir -p logs/llm_interactions upload cache \
    && chmod 777 /usr/local/src/LogonTracer \
    && chmod 777 /usr/local/src/LogonTracer/static \
    && chmod 777 /usr/local/src/LogonTracer/logs \
    && chmod 777 /usr/local/src/LogonTracer/upload \
    && chmod 777 /usr/local/src/LogonTracer/cache

WORKDIR /usr/local/src

RUN echo "#!/bin/bash" > run.sh \
    && echo "sleep 60" >> run.sh \
    && echo "cd /usr/local/src/LogonTracer" >> run.sh \
    && echo "python logontracer.py -r -o 8080 -u neo4j -p password -s \${LTHOSTNAME:-neo4j}" >> run.sh \
    && chmod 755 run.sh

EXPOSE 8080

CMD ["/usr/local/src/run.sh"]
