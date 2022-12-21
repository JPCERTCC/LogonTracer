# LogonTracer with SSL

  Enable SSL communication with LogonTracer and nginx.

  Please check the wiki for more details.   
  https://github.com/JPCERTCC/LogonTracer/wiki/setup-LogonTracer-with-SSL

## Usage
### Download LogonTracer

  ```shell
  $ git clone https://github.com/JPCERTCC/LogonTracer.git
  ```

### Get Your SSL Certificate

The following describes how to create a self-signed SSL certificate. If you can buy an SSL certificate, consider other options.

#### Command for creating a self-signed SSL certificate

  ```shell
  $ openssl req -new -days 365 -x509 -nodes -keyout server.key -out server.crt
  ```

### Set Your SSL Certificate

  ```shell
  $ cp server.key LogonTracer/docker-compose-with-nginx/nginx/
  $ cp server.crt LogonTracer/docker-compose-with-nginx/nginx/
  $ cp server.key LogonTracer/docker-compose-with-nginx/neo4j/certificates/bolt/
  $ cp server.crt LogonTracer/docker-compose-with-nginx/neo4j/certificates/bolt/
  ```

### Docker Build and Start

  ```shell
  $ cd LogonTracer/docker-compose-with-nginx/
  $ docker-compose build
  $ docker-compose up -d
  ```

### Accessing the Web GUI

Access **https://[LogonTracer_Server]/** via Web browser. Please make sure to enable JavaScript on your browser.

#### Note

If you are using a self-signed SSL certificate, it will be rejected by your web browser. Please set your web browser to allow SSL certificates as HTTPS.

* Import self-signed SSL certificate for Web browser.

  `or`

* Allow SSL certificate from web browser warning messages.

  1. Access to **https://[LogonTracer_Server]/** and allow the SSL certificate.

  2. Access to **https://[LogonTracer_Server]:7678/** and allow the SSL certificate.
