FROM ubuntu:14.04

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y

RUN useradd -m -s /bin/bash scion
RUN echo "scion ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/scion

# Pre-install some of the largest indirect dependancies, to speed up rebuild when
# scion.sh changes for any reason.
RUN DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y build-essential default-jre-headless
# Pre-download some of the known major dependancies, to speed up rebuilds.
RUN DEBIAN_FRONTEND=noninteractive apt-get install --download-only --no-install-recommends -y python python3 python-dev python3-dev screen zookeeperd


# Just copy over scion.sh for now, to install dependancies. Don't want docker
# to re-run this step everytime anything in the repo changes.
COPY _build/scion.git/scion.sh /home/scion/scion.git/
RUN chown -R scion: /home/scion
USER scion
ENV HOME /home/scion
WORKDIR /home/scion/scion.git
RUN DEBIAN_FRONTEND=noninteractive APTARGS=-y ./scion.sh deps
RUN echo "PATH=$HOME/.local/bin:$PATH" >> ~/.profile

USER root
# Clean out the cached packages now they're no longer necessary
RUN apt-get clean

# Now copy over the current branch
COPY _build/scion.git /home/scion/scion.git
RUN chown -R scion: /home/scion

USER scion
CMD ["bash", "-l"]
