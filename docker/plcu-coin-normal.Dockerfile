FROM registry.dramaco.tech/plc-ultima/plcu-node-base:2

ARG PLCULTIMA_VERSION

ENV PLCULTIMA_VERSION=$PLCULTIMA_VERSION
ENV PLCULTIMA_DATA=/root/.plcultima

COPY docker/docker-entrypoint-normal.sh /entrypoint.sh
COPY docker/plcultima.conf /etc/plcultima.conf
COPY build/debian/usr/local/bin/plcultimad /usr/bin/plcultimad

RUN chmod 755 /entrypoint.sh

VOLUME ["/root/.plcultima"]

#       zmq rpc health p2p
EXPOSE 9331 9332 9833 9835

ENTRYPOINT ["/entrypoint.sh"]

CMD ["plcultimad"]