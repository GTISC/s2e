# ================
# First stage: install s2e-env and build s2e
FROM ubuntu:22.04 as builder

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
RUN apt update && apt install -y --fix-missing qemu qemu-kvm git curl wget lsb-release sudo gcc python3 python3-dev python3-venv python3-pip python-is-python3

RUN useradd -m s2e && echo "s2e:s2e" | chpasswd && adduser s2e sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER s2e

# install s2e-env for building s2e
RUN cd /home/s2e && git clone https://github.com/GTISC/s2e-env.git
WORKDIR /home/s2e/s2e-env
ENV PATH=$PATH:/home/s2e/.local/bin
RUN pip install --upgrade pip && pip install .

# build s2e
ARG TARGET_BRANCH=master
RUN s2e init /home/s2e/s2e -sb $TARGET_BRANCH
WORKDIR /home/s2e/s2e
SHELL ["/bin/bash", "-c"]
RUN source s2e_activate
RUN s2e update
RUN s2e build

# clean up
USER root
RUN rm -rf build source/.repo source/s2e-linux-kernel source/s2e-env source/s2e source/qemu

# ================
# Second stage: install s2e-env and copy over the built s2e
FROM ubuntu:22.04 as necessary

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC 
ENV PATH=$PATH:/home/s2e/.local/bin

# We need to install two more things to make it work: jq and libmagic1
RUN apt update && apt install -y --fix-missing qemu qemu-kvm \
        git curl wget lsb-release sudo gcc python3 python3-dev \
        python3-venv python3-pip python-is-python3 \
        jq libmagic1

RUN useradd -m s2e && echo "s2e:s2e" | chpasswd && adduser s2e sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER s2e

# install s2e-env for running s2e
RUN cd /home/s2e && git clone https://github.com/GTISC/s2e-env.git \
    && cd /home/s2e/s2e-env && pip install --upgrade pip && pip install .

COPY --from=builder /home/s2e/s2e /home/s2e/s2e
# We also have to copy the libs, otherwise, qemu won't work
COPY --from=builder /usr/lib/x86_64-linux-gnu/ /usr/lib/x86_64-linux-gnu/

# ================
# Third stage: flatten everything into one layer
FROM scratch
COPY --from=necessary / /
USER s2e
ENV PATH=$PATH:/home/s2e/.local/bin
WORKDIR /home/s2e