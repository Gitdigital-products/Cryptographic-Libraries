FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    clang \
    llvm-dev \
    libtool-bin \
    make \
    autoconf \
    automake \
    pkg-config \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN CC=clang CXX=clang++ make fuzz

# Create corpus directory
RUN mkdir -p /corpus
COPY tests/fuzz/corpus/* /corpus/

ENTRYPOINT ["./build/fuzz_sha2"]