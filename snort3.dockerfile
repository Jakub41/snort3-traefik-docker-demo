FROM ubuntu:latest

## Install Dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -yq \
    wget \
    build-essential \
    libpcap-dev \
    libpcre3-dev \
    libnet1-dev \
    zlib1g-dev \
    luajit \
    hwloc \
    libdnet-dev \
    libdumbnet-dev \
    bison \
    flex \
    liblzma-dev \
    openssl \
    libssl-dev \
    pkg-config \
    libhwloc-dev \
    cmake \
    cpputest \
    libsqlite3-dev \
    uuid-dev \
    libcmocka-dev \
    libnetfilter-queue-dev \
    libmnl-dev \
    autotools-dev \
    libluajit-5.1-dev \
    libunwind-dev \
    && apt-get clean && rm -rf /var/cache/apt/*

# Define working directory.
WORKDIR /opt

# DAQ
ENV DAQ_VERSION 3.0.3
RUN wget https://github.com/snort3/libdaq/archive/refs/tags/v${DAQ_VERSION}.tar.gz \
    && tar xvfz v${DAQ_VERSION}.tar.gz \
    && cd libdaq-${DAQ_VERSION} \
    && ./bootstrap \
    && ./configure \
    && make \
    && make install

RUN ldconfig 

# Snort 3.1.0
ENV MY_PATH=/usr/local/snort
ENV SNORT_VERSION 3.1.5.0
RUN wget https://github.com/snort3/snort3/archive/refs/tags/${SNORT_VERSION}.tar.gz \
    && tar xvfz ${SNORT_VERSION}.tar.gz \
    && cd snort3-${SNORT_VERSION} \
    && ./configure_cmake.sh --prefix=${MY_PATH} \
    && cd build \
    && make -j $(nproc) install 

RUN ldconfig

# For this to work you MUST have downloaded the snort3 subscribers ruleset.
# This has to be located in the directory we are currently in.
ENV SNORT_RULES_SNAPSHOT 3150
COPY snortrules-snapshot-${SNORT_RULES_SNAPSHOT}.tar.gz /opt/
RUN cd /opt/ \
    && tar xvfz snortrules-snapshot-${SNORT_RULES_SNAPSHOT}.tar.gz \
    && ls -la && sleep 20

COPY entrypoint.sh /opt

RUN mkdir -p /var/log/snort && \
    mkdir -p /usr/local/lib/snort_dynamicrules && \
    mkdir -p /etc/snort && \
    mkdir -p /etc/snort/rules && \
    mkdir -p /etc/snort/preproc_rules && \
    mkdir -p /etc/snort/etc && \

    cp -r /opt/rules /etc/snort && \
    cp -r /opt/so_rules /etc/snort && \
    cp -r /opt/etc /etc/snort && \

    touch /etc/snort/rules/local.rules && \
    touch /etc/snort/rules/white_list.rules /etc/snort/rules/black_list.rules

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    /opt/snort-${SNORT_VERSION}.tar.gz /opt/daq-${DAQ_VERSION}.tar.gz

ENV INTERFACE 'lo0'
ENV LUA_PATH=${MY_PATH}/include/snort/lua/\?.lua\;\;
ENV SNORT_LUA_PATH=${MY_PATH}/etc/snort

# Validate an installation
RUN ${MY_PATH}/bin/snort -c /etc/snort/etc/snort.lua && sleep 60
RUN chmod a+x /opt/entrypoint.sh

# Let's run snort!
CMD ["-i", "lo0"]
ENTRYPOINT ["/opt/entrypoint.sh"]
#CMD ["/usr/local/snort/bin/snort", "-d", "-i", "eth0", "-c", "/etc/snort/etc/snort.lua"]

