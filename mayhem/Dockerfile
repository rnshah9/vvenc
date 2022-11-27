FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y clang

COPY . /repo
WORKDIR /repo/build
RUN CC=clang CXX=clang++ cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install

RUN clang++ /repo/mayhem/fuzz_vvenc_set_SIMD_extension.cpp -fsanitize=address,fuzzer -I /install/include/ -L /install/lib/ -lvvenc -flto -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /install /install
COPY --from=builder /repo/test/data/RTn23_80x44p15_f15.yuv /repo/test/data/RTn23_80x44p15_f15.yuv
COPY --from=builder /fuzz /fuzz_vvenc_set_SIMD_extension