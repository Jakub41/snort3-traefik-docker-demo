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
    iproute2 \
    net-tools \
    sudo \
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

# OpenAppID - Device detection
ENV OPEN_APP_ID 17843
RUN wget https://www.snort.org/downloads/openappid/${OPEN_APP_ID}  -O OpenAppId-${OPEN_APP_ID}.tgz \
    && tar xvfz OpenAppId-${OPEN_APP_ID}.tgz \
    && cp -R odp /usr/local/lib/
 
# For this to work you MUST have downloaded the snort3 subscribers ruleset.
# This has to be located in the directory we are currently in.
ENV SNORT_RULES_SNAPSHOT 3150
COPY snortrules-snapshot-${SNORT_RULES_SNAPSHOT} /opt/

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
    cp -r /opt/builtins /etc/snort && \

    touch /etc/snort/rules/local.rules && \
    touch /etc/snort/rules/white_list.rules /etc/snort/rules/black_list.rules

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    /opt/${SNORT_VERSION}.tar.gz /opt/v${DAQ_VERSION}.tar.gz

ENV INTERFACE 'eth0'
ENV LUA_PATH=${MY_PATH}/include/snort/lua/\?.lua\;\;
ENV SNORT_LUA_PATH=${MY_PATH}/etc/snort
ENV PATH="/usr/local/snort/bin:$PATH"

# Validate an installation
RUN ${MY_PATH}/bin/snort -c /etc/snort/etc/snort.lua
RUN chmod a+x /opt/entrypoint.sh

# Set net interfaace to promiscous mode to detect traffic efficiently
#"RUN ip address && sleep 60
# RUN ip link set dev ${INTERFACE} promisc on

# Make Snort intercept larger packegages
# Preventing from truncating large packets larger than 1518 bytes
# RUN ethtool -K ${INTERFACE} gro off lro off

# Persist the NIC and enable service
# COPY snort3-nic.service /etc/systemd/system/
# RUN systemctl daemon-reload && systemctl enable --now snort3-nic.service

# Let's run snort!
# CMD ["-i", "eth0"]
ENTRYPOINT ["/opt/entrypoint.sh"]
# CMD ["/usr/local/snort/bin/snort", "-d", "-i", "eth0", "-c", "/etc/snort/etc/snort.lua"]
CMD ["/usr/local/snort/bin/snort", "-i", "eth0", "-c", "/etc/snort/etc/snort.lua", "-A", "full", "-s", "6000" "-k" "none"]