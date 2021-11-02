ARG DISTRIB
FROM $DISTRIB
ARG DISTRIB
RUN echo 'DISTRIB: ' $DISTRIB

ENV MAINDIR=/tmp/plc-coin
WORKDIR $MAINDIR

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        autoconf \
        automake \
        autopoint \
        autotools-dev \
        bsdmainutils \
        build-essential \
        libboost-all-dev \
        libdb-dev \
        libdb++-dev \
        libevent-dev \
        libprotobuf-dev \
        libqt5core5a \ 
        libqt5dbus5 \
        libqt5gui5 \
        libsecp256k1-dev \
        libssl-dev \
        libtool \
        libzmq3-dev \
        make \
        p7zip-full \
        pkg-config \
        protobuf-compiler \
        python3-pip \
        python3-zmq \
        qttools5-dev \
        qttools5-dev-tools \
        software-properties-common

COPY test/plc_cryptonight.tar.gz $MAINDIR/test/plc_cryptonight.tar.gz
RUN pip3 install --upgrade test/plc_cryptonight.tar.gz

COPY test/requirements.txt $MAINDIR/test/requirements.txt
RUN pip3 install --requirement test/requirements.txt

COPY . $MAINDIR

# Build:
RUN ./autogen.sh
RUN ./configure --with-incompatible-bdb
RUN make -j4
RUN make install-strip DESTDIR=/tmp/build/debian

# Debian tests:
RUN make check VERBOSE=1

# Extended tests:
RUN python3 test/functional/test_runner.py --extended
