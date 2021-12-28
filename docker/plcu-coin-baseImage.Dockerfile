FROM debian:buster-slim

RUN apt-get update -y \
    && apt-get upgrade -y \
    && apt-get -y install gettext wget nginx curl\
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY docker/health.template /etc/nginx/