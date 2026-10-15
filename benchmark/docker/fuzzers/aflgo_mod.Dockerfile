FROM dgf-base:latest

ENV FUZZER_NAME="aflgo_mod"
ENV AFLGO="/fuzzer/aflgo-mod"
ENV AFLGO_ROOT="/fuzzer/aflgo-mod"
ENV PATH="${AFLGO}/instrument:${AFLGO}/afl-2.57b:${PATH}"

ARG REPO_URL="https://github.com/cooN4i/aflgo-research.git"
ARG REPO_BRANCH="develop"
ARG COMMIT_SHA=""

# Clone modified AFLGo source tree from GitHub
RUN git clone --depth 1 -b ${REPO_BRANCH} ${REPO_URL} /tmp/repo && \
    mkdir -p /fuzzer && \
    cp -r /tmp/repo/aflgo-mod /fuzzer/aflgo-mod && \
    rm -rf /tmp/repo

# Build AFL core binaries and modified LLVM pass
WORKDIR /fuzzer/aflgo-mod
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
