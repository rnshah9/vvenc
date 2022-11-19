FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install

FROM ubuntu:22.04 as package
COPY --from=builder /install /install
COPY --from=builder /repo/test/data/RTn23_80x44p15_f15.yuv /repo/test/data/RTn23_80x44p15_f15.yuv