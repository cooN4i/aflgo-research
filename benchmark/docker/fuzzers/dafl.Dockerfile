FROM dgf-base:latest

ENV FUZZER_NAME="dafl"
ENV DAFL="/fuzzer/dafl"
# Clone DAFL (Directed Grey-Box Fuzzer based on AFL 2.57b from KAIST Prosys Lab)
RUN git clone --depth 1 https://github.com/prosyslab/DAFL.git /fuzzer/dafl && \
    cd /fuzzer/dafl && \
    make clean && \
    make -j$(nproc) && \
    cd llvm_mode && \
    sed -i '1i #include <llvm/IR/DebugInfoMetadata.h>' afl-llvm-pass.so.cc && \
    make -j$(nproc)

ENV PATH="${DAFL}:${DAFL}/llvm_mode:${PATH}"
WORKDIR /workspace
