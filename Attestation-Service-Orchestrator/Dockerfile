FROM ubuntu:18.04

RUN apt-get update -y && apt-get install -y g++ build-essential autoconf cmake libssl-dev wget libtool pkg-config libgmp3-dev libcpprest-dev libboost-all-dev git

COPY . /app

RUN mkdir /opt/ibmtpm && tar -xzf /app/ibmtpm.tar.gz -C /opt/ibmtpm && rm /app/ibmtpm.tar.gz
RUN mkdir /opt/ibmtss && tar -xzf /app/ibmtss.tar.gz -C /opt/ibmtss && rm /app/ibmtss.tar.gz

ADD NVChip /opt/ibmtpm/src
WORKDIR /opt/ibmtpm/src
RUN make

WORKDIR /opt/ibmtss
RUN autoreconf -i
RUN ./configure --prefix=/usr/local --disable-tpm-1.2 --disable-hwtpm
RUN make
RUN make install
RUN ldconfig -v

WORKDIR /app/libs
RUN ./build_dependencies.sh

WORKDIR /app
RUN cmake .
RUN make

ENTRYPOINT [ "/app/run.sh" ]
# CMD [ "-api http://host.docker.internal:8080/api -ha 0x01001500 -nv" ]
