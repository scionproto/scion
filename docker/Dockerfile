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

################################################################################
# Handle installing all dependancies up-front. That way code changes don't cause
# the expensive part of the image build to be re-run.
################################################################################

# Copy over scion.sh. If it has changed, everything gets rebuilt.
USER scion
ENV HOME /home/scion
WORKDIR /home/scion/scion.git
COPY scion.git/scion.sh /home/scion/scion.git/

# Copy over pkgs_debian.txt. If it has changed, then re-run the remaining steps.
COPY scion.git/pkgs_debian.txt /home/scion/scion.git/
RUN sudo chown -R scion: /home/scion
RUN DEBIAN_FRONTEND=noninteractive APTARGS=-y ./scion.sh deps pkgs

# Copy over requirements.txt. If it has changed, then re-run the remaining steps.
COPY scion.git/requirements.txt /home/scion/scion.git/
RUN sudo chown -R scion: /home/scion
RUN ./scion.sh deps pip3

RUN ./scion.sh deps

# Clean out the cached packages now they're no longer necessary
RUN sudo apt-get clean

################################################################################
# All dependancies are now installed, carry on with the rest.
################################################################################

RUN echo "PATH=$HOME/.local/bin:/usr/share/zookeeper/bin:$PATH" >> ~/.profile
# Now copy over the current branch
COPY scion.git /home/scion/scion.git
# Copy over init.sh:
COPY scion.git/docker/init.sh /home/scion/bin/
# Install basic screen config
COPY scion.git/docker/screenrc /home/scion/.screenrc

# Fix ownership one last time:
RUN sudo chown -R scion: /home/scion
# Fix some image problems:
RUN sudo chmod g+s /usr/bin/screen

CMD ["/home/scion/bin/init.sh"]
