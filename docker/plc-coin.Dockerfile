FROM debian:buster-slim

ARG PLCULTIMA_VERSION

ENV PLCULTIMA_VERSION=$PLCULTIMA_VERSION
ENV PLCULTIMA_DATA=/home/plcultima/.plcultima

COPY docker/docker-entrypoint.sh /entrypoint.sh
COPY build/debian/usr/local/bin/plcultimad /usr/bin/plcultimad
COPY build/debian/usr/local/bin/plcultima-cli /usr/bin/plcultima-cli

RUN useradd -r plcultima \
    && apt-get update -y \
    && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && set -ex \
    && chmod 755 /entrypoint.sh


VOLUME ["/home/plcultima/.plcultima"]

EXPOSE 19330 19331

ENTRYPOINT ["/entrypoint.sh"]

CMD ["plcultimad"]