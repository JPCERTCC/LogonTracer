FROM python:3.7.8-slim-buster

RUN set -ex \
  	\
  	&& savedAptMark="$(apt-mark showmanual)" \
    && apt-get update \
    && apt-get install -y --no-install-recommends git \
		dpkg-dev \
		gcc \
		libssl-dev \
		make \
		curl \
        build-essential

## LogonTracer install
WORKDIR /usr/local/src

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN git clone https://github.com/JPCERTCC/LogonTracer.git \
    && chmod 777 LogonTracer \
		&& chmod 777 LogonTracer/static \
    && cd LogonTracer \
    && pip install cython \
    && pip install numpy \
    && pip install scipy \
    && pip install statsmodels \
    && pip install -r requirements.txt \
    && sed -i 's/\" -s \" + NEO4J_SERVER/\" -s neo4j\"/g' logontracer.py \
    && sed -i 's/+ NEO4J_SERVER +/+ \"neo4j\" +/g' logontracer.py \
    && sed -i 's/host=NEO4J_SERVER/host=\"neo4j\"/g' logontracer.py

## Create setup file
WORKDIR /usr/local/src

RUN echo "#!/bin/bash" > run.sh \
    && echo "sleep 60" >> run.sh \
    && echo "cd /usr/local/src/LogonTracer" >> run.sh \
    && echo "python logontracer.py -r -o 8080 -u neo4j -p password -s \${LTHOSTNAME}" >> run.sh \
    && chmod 755 run.sh

EXPOSE 8080

CMD ["/usr/local/src/run.sh"]
