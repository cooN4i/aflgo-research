FROM dgf-base:latest

ENV FUZZER_NAME="fishfuzz"
ENV FISHFUZZ="/fuzzer/fishfuzz"
ENV FF_AFL="/fuzzer/fishfuzz/FF_AFL"

# Install FishFuzz specific dependencies (glib, graphviz cgraph, jsoncpp)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-dev \
    libgraphviz-dev \
    libjsoncpp-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone FishFuzz (USENIX Security 2023 from EPFL HexHive)
RUN git clone --depth 1 https://github.com/HexHive/FishFuzz.git /fuzzer/fishfuzz && \
    cd /fuzzer/fishfuzz/FF_AFL && \
    make -C llvm_mode && \
    make -C dyncfg CXXFLAGS="-I/usr/include/jsoncpp" && \
    AFL_NO_X86=1 make -j$(nproc) && \
    chmod +x scripts/*.py

ENV AFL_PATH="${FF_AFL}"
ENV CC="${FF_AFL}/afl-clang-fast"
ENV CXX="${FF_AFL}/afl-clang-fast++"
ENV PATH="${FF_AFL}:${FF_AFL}/scripts:${PATH}"
WORKDIR /workspace
