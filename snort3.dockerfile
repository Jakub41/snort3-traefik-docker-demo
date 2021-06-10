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
    ethtool \
    libtool \
    git \
    autoconf \
    ragel \
    libboost-dev \
    libboost-all-dev \
    systemd \
    libcrypt-ssleay-perl \ 
    liblwp-useragent-determined-perl \
    && apt-get clean && rm -rf /var/cache/apt/*

# Define working directory.
WORKDIR /opt

# Safec for runtime bounds checks on certain legacy C-library calls
ENV SAFEC_VERSION 02092020
RUN wget https://github.com/rurban/safeclib/releases/download/v02092020/libsafec-${SAFEC_VERSION}.tar.gz \
    && tar xvfz libsafec-${SAFEC_VERSION}.tar.gz \
    && cd libsafec-${SAFEC_VERSION}.0-g6d921f \
    && ./configure \ 
    && make \ 
    && sudo make install

# Hyperscan critical to Snort3 operations and performance
# uses to fast pattern matching
# dependencies: PCRE, gperftools, ragel, Boost C++, flatbuffers, colm
ENV PCRE_VERSION 10.37
RUN wget https://ftp.pcre.org/pub/pcre/pcre2-${PCRE_VERSION}.tar.gz \
    && tar xzvf pcre2-${PCRE_VERSION}.tar.gz \
    && cd pcre2-${PCRE_VERSION} \
    && ./configure && make && sudo make install

ENV GP_TOOLS_VERSION 2.9.1
RUN wget https://github.com/gperftools/gperftools/releases/download/gperftools-${GP_TOOLS_VERSION}/gperftools-${GP_TOOLS_VERSION}.tar.gz \
    && tar xzvf gperftools-${GP_TOOLS_VERSION}.tar.gz \
    && cd gperftools-${GP_TOOLS_VERSION} \
    && ./configure && make && sudo make install

ENV HYPERSCAN_VESRSION 5.4.0-2
RUN wget https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/hyperscan/5.4.0-2/hyperscan_5.4.0.orig.tar.gz \
    && tar xvzf hyperscan_5.4.0.orig.tar.gz \
    && mkdir hyperscan-${HYPERSCAN_VESRSION}-build \
    && cd hyperscan-${HYPERSCAN_VESRSION}-build \
    && cmake -DCMAKE_INSTALL_PREFIX=/usr/local ../hyperscan-5.4.0 \
    && make && sudo make install

ENV FLATBUFFERS_VESRSION 2.0.0
RUN wget https://github.com/google/flatbuffers/archive/refs/tags/v${FLATBUFFERS_VESRSION}.tar.gz -O flatbuffers-v${FLATBUFFERS_VESRSION}.tar.gz \
    && tar xvzf flatbuffers-v${FLATBUFFERS_VESRSION}.tar.gz \
    && mkdir flatbuffers-build \
    && cd flatbuffers-build \
    && cmake ../flatbuffers-${FLATBUFFERS_VESRSION} \
    && make && sudo make install

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

COPY *.sh /opt

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

    # Custom rules goes to local.rules 
    # Will be copied an external file to Docker
    # COPY local.rules /etc/snort/rules/local.rules
    touch /etc/snort/rules/local.rules && \
    touch /etc/snort/rules/white_list.rules /etc/snort/rules/black_list.rules

# Pulledpork
RUN wget https://github.com/shirkdog/pulledpork/archive/master.tar.gz -O pulledpork-master.tar.gz \
    && tar xzvf pulledpork-master.tar.gz \
    && cd pulledpork-master \
    && cp pulledpork.pl /usr/bin/ \
    && chmod 755 /usr/bin/pulledpork.pl \
    && cp etc/* /etc/snort/ \
    && cpan install LWP::Protocol::https \
    && cpan install Crypt::SSLeay  \
    && cpan Mozilla::CA IO::Socket::SSL

# Check Pulledpork was installed
RUN /usr/bin/pulledpork.pl -V && sleep 15

# Pulledpork conf
COPY pulledpork.conf /etc/snort/pulledpork.conf
COPY disablesid.conf /etc/snort/disablesid.conf

# COPY local rules across
COPY /rules/local.rules /etc/snort/rules/local.rules

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    /opt/${SNORT_VERSION}.tar.gz /opt/v${DAQ_VERSION}.tar.gz

ENV INTERFACE 'eth0'
ENV LUA_PATH=${MY_PATH}/include/snort/lua/\?.lua\;\;
ENV SNORT_LUA_PATH=${MY_PATH}/etc/snort
ENV PATH="/usr/local/snort/bin:$PATH"

# To check what that dir contains
# RUN cd /usr/local/snort/bin/ && ls -la && sleep 30

# Network interface service --> Not working
# RUN ls -la /lib/systemd/system/ && sleep 30
# COPY ethtool.service /lib/systemd/system/
# RUN sudo service enable --now ethtool \ 
#     && sudo service ethtool start

# HOME_NET config --> chage this with the right IP adresses where snort should monitoring
ARG SNORT_HOME_NET="172.19.0.0/24,192.168.65.0/24"
RUN sed -i "s#^HOME_NET =.*#HOME_NET = '$SNORT_HOME_NET'#" /etc/snort/etc/snort.lua

# Validate an installation
RUN ${MY_PATH}/bin/snort -c /etc/snort/etc/snort.lua
RUN chmod a+x /opt/*

# Add the script that allows the rules to be updated when the container is running
ARG PPORK_OINKCODE
RUN if [ ! -z $PPORK_OINKCODE ]; then  bash update-rules.sh "$PPORK_OINKCODE"; fi

# Exposed port
EXPOSE 8080
# Let's run snort!
CMD ["-i", "eth0", "-A", "full", "-s", "65535", "-k", "none"]
ENTRYPOINT ["/opt/entrypoint.sh"]
# CMD ["/usr/local/snort/bin/snort", "-d", "-i", "eth0", "-c", "/etc/snort/etc/snort.lua"]
# CMD ["/usr/local/snort/bin/snort", "-i", "eth0", "-c", "/etc/snort/etc/snort.lua", "-A", "fast", "-s", "65535", "-k", "none"]