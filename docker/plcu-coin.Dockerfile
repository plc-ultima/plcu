FROM registry.dramaco.tech/plc-ultima/plcu-node-base:2

ARG PLCULTIMA_VERSION

ENV PLCULTIMA_VERSION=$PLCULTIMA_VERSION
ENV PLCULTIMA_DATA=/root/.plcultima
ENV PLCULTIMA_RPC_USERNAME=ultimauser
ENV PLCULTIMA_RPC_PASSWORD=ultimapassword

COPY docker/docker-entrypoint.sh /entrypoint.sh
COPY docker/plcultima.conf /etc/plcultima.conf
COPY build/debian/usr/local/bin/plcultimad /usr/bin/plcultimad
COPY build/debian/usr/local/bin/plcultima-cli /usr/bin/plcultima-cli

RUN chmod 755 /entrypoint.sh

VOLUME ["/root/.plcultima"]

#       zmq rpc health p2p
EXPOSE 9331 9332 9833 9835

ENTRYPOINT ["/entrypoint.sh"]

CMD ["plcultimad"]
