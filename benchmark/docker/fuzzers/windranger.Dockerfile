FROM dgf-base:latest

ENV FUZZER_NAME="windranger"
ENV WINDRANGER="/fuzzer/WindRanger"
ENV PATH="${WINDRANGER}/instrument/bin:${WINDRANGER}/fuzz:${PATH}"

# Install wllvm / gllvm prerequisites, libtinfo5 for cbi, and wget
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pip \
    libtinfo5 \
    wget \
    ca-certificates \
    && pip3 install --no-cache-dir wllvm \
    && rm -rf /var/lib/apt/lists/*

# Download and extract canonical WindRanger build from repository
RUN mkdir -p /fuzzer && \
    wget https://raw.githubusercontent.com/prosyslab/DAFL-artifact/main/docker-setup/windranger.tar.gz -O /fuzzer/windranger.tar.gz && \
    cd /fuzzer && \
    tar -xzf windranger.tar.gz && \
    rm windranger.tar.gz && \
    mv windranger WindRanger && \
    cd WindRanger/fuzz && \
    make clean && \
    make afl-fuzz afl-showmap afl-tmin afl-gotcpu afl-analyze -j$(nproc) && \
    make -C llvm_mode

ENV CC="${WINDRANGER}/fuzz/afl-clang-fast"
ENV CXX="${WINDRANGER}/fuzz/afl-clang-fast++"
WORKDIR /workspace
