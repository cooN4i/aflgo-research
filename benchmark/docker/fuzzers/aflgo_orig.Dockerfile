FROM dgf-base:latest

ENV FUZZER_NAME="aflgo_orig"
ENV AFLGO="/fuzzer/aflgo-orig"
ENV AFLGO_ROOT="/fuzzer/aflgo-orig"
ENV PATH="${AFLGO}/instrument:${AFLGO}/afl-2.57b:${PATH}"

ARG REPO_URL="https://github.com/cooN4i/aflgo-research.git"
ARG REPO_BRANCH="develop"
ARG COMMIT_SHA=""

# Clone original AFLGo source tree from GitHub
RUN git clone --depth 1 -b ${REPO_BRANCH} ${REPO_URL} /tmp/repo && \
    mkdir -p /fuzzer && \
    cp -r /tmp/repo/aflgo-orig /fuzzer/aflgo-orig && \
    rm -rf /tmp/repo

# Build AFL core binaries and LLVM pass
WORKDIR /fuzzer/aflgo-orig
RUN cd afl-2.57b && \
    make clean && \
    make afl-fuzz afl-gcc afl-as afl-showmap afl-tmin afl-gotcpu afl-analyze -j$(nproc)

RUN cd instrument && \
    make clean && \
    make -j$(nproc)

# Build distance calculator
RUN cd distance/distance_calculator && \
    cmake . && \
    make -j$(nproc)

WORKDIR /workspace
