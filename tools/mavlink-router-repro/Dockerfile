FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates build-essential meson ninja-build pkg-config \
      python3 python3-future \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Pinned to the exact commit behind the recorded measurement, so the build is
# reproducible and the numbers are comparable.
RUN git clone https://github.com/mavlink-router/mavlink-router.git \
 && cd mavlink-router \
 && git checkout 2362c62 \
 && git submodule update --init --recursive \
 && meson setup build . -Dsystemdsystemunitdir=/tmp \
 && ninja -C build

COPY probe.py /probe.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
