FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install essential compilation, debugging and graph analysis dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang-11 \
    llvm-11 \
    llvm-11-dev \
    llvm-11-tools \
    libclang-11-dev \
    binutils-gold \
    bison \
    flex \
    texinfo \
    cmake \
    automake \
    autoconf \
    libtool \
    pkg-config \
    git \
    wget \
    curl \
    python3 \
    python3-dev \
    python3-pip \
    libboost-all-dev \
    gdb \
    libarchive-tools \
    graphviz \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set clang-11 as default compiler and configure gold linker
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-11 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-11 100 && \
    update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-11 100 && \
    update-alternatives --install /usr/bin/ld ld /usr/bin/ld.gold 100 && \
    mkdir -p /usr/lib/bfd-plugins && \
    ln -sf /usr/lib/llvm-11/lib/LLVMgold.so /usr/lib/bfd-plugins/LLVMgold.so

# Install Python packages required for graph distance calculations and metrics
RUN pip3 install --no-cache-dir \
    networkx \
    "pydot<3.0.0" \
    pydotplus \
    pyyaml \
    pandas \
    scipy \
    matplotlib

# Environment settings
ENV CC=clang
ENV CXX=clang++
ENV LLVM_CONFIG=llvm-config

WORKDIR /workspace
