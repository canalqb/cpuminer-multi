#
# Dockerfile do cpuminer-multi (@CanalQb)
#
# Uso básico:
#   docker build -t cpuminer-multi .
#   docker run cpuminer-multi --url <URL_DO_POOL> --user <USUARIO.TRABALHADOR> --pass x
#
# Otimização para a CPU:
#   Por padrão a imagem usa flags genéricas (portável entre hosts).
#   Se a imagem for rodar na MESMA máquina que compilou, use:
#   docker build --build-arg MARCH=-march=native -t cpuminer-multi .
#
# Aviso de segurança:
#   - O container roda como root por padrão. Para rodar como usuário comum,
#     adicione: docker run --user $(id -u):$(id -g) ...
#   - Este minerador exige CPU com AES-NI (verifique com `lscpu | grep aes`).

FROM ubuntu:22.04

LABEL maintainer="CanalQb <qrodrigob@gmail.com>"

ENV DEBIAN_FRONTEND=noninteractive

# Flags de compilação da CPU. "-march=native" otimiza para a máquina atual.
ARG MARCH=

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
        build-essential \
        autoconf \
        automake \
        libtool \
        pkg-config \
        libcurl4-openssl-dev \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /cpuminer
RUN git clone https://github.com/canalqb/cpuminer-multi.git .
RUN ./autogen.sh
RUN CFLAGS="${MARCH} -O3" ./configure
RUN make -j"$(nproc)"

WORKDIR /cpuminer
ENTRYPOINT ["./minerd"]
