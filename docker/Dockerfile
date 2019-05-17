FROM neo4j:3.2.3

RUN apk add --no-cache --virtual build-temp \
    build-base \
    bzip2-dev \
    coreutils \
    dpkg-dev dpkg \
    expat-dev \
    gdbm-dev \
    linux-headers \
    ncurses-dev \
    openssl \
    openssl-dev \
    pax-utils \
    readline-dev \
    sqlite-dev \
    tcl-dev \
    tk \
    tk-dev \
    xz-dev \
    gfortran \
    zlib-dev \
    git
RUN apk add --no-cache \
    bash \
    curl \
    python \
    py-pip \
    libssl1.1

## python3.6 and modules install
ENV PYTHON_VERSION=3.6.2 \
    LANG=C.UTF-8

WORKDIR /usr/local/src
RUN apk add --no-cache lapack-dev\
    libxml2-dev \
    libxslt-dev \
    && curl --fail --silent --show-error --location --output python.tgz https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz \
    && tar zxf python.tgz \
    && rm python.tgz \
    && cd Python-${PYTHON_VERSION} \
    && ./configure \
    && make altinstall \
    && ln -s /usr/local/bin/python3.6 /usr/local/bin/python3 \
    && pip install supervisor
ENV PYTHONIOENCODING=utf-8

## LogonTracer install
WORKDIR /usr/local/src

RUN git clone https://github.com/JPCERTCC/LogonTracer.git \
    && cd LogonTracer \
    && pip3.6 install --upgrade pip \
    && pip3.6 install --upgrade setuptools \
    && pip3.6 install numpy \
    && pip3.6 install -r requirements.txt \
    && unlink /var/lib/neo4j/data \
    && mkdir -p /var/lib/neo4j/data/databases \
    && tar xzf sample/graph.db.tar.gz -C /var/lib/neo4j/data/databases \
    && echo "dbms.allow_format_migration=true" >> /var/lib/neo4j/conf/neo4j.conf

## Create supervisord.conf
RUN touch /etc/supervisord.conf \
    && echo "[supervisord]"  >> /etc/supervisord.conf \
    && echo "nodaemon=true"  >> /etc/supervisord.conf \
    && echo "[program:neo4j]" >> /etc/supervisord.conf \
    && echo "command=/docker-entrypoint.sh neo4j"   >> /etc/supervisord.conf \
    && echo "[program:logontracer]" >> /etc/supervisord.conf \
    && echo "command=/usr/local/src/run.sh"   >> /etc/supervisord.conf \
    && echo "[program:setup]" >> /etc/supervisord.conf \
    && echo "command=/usr/local/src/setup.sh"   >> /etc/supervisord.conf

## Create setup file
RUN echo "#!/bin/bash" > setup.sh \
    && echo "sleep 40" >> setup.sh \
    && echo "curl -H \"Content-Type: application/json\" -X POST -d '{\"password\":\"password\"}' -u neo4j:neo4j http://localhost:7474/user/neo4j/password" >> setup.sh \
    && echo "rm -f /usr/local/src/setup.sh" >> setup.sh \
    && chmod 755 setup.sh
RUN echo "#!/bin/bash" > run.sh \
    && echo "sleep 40" >> run.sh \
    && echo "cd /usr/local/src/LogonTracer" >> run.sh \
    && echo "python3 logontracer.py -r -o 8080 -u neo4j -p password -s \${LTHOSTNAME}" >> run.sh \
    && chmod 755 run.sh

## delete build apk
WORKDIR /var/lib/neo4j
RUN apk del --purge build-temp

EXPOSE 8080

CMD ["supervisord", "-n"]
