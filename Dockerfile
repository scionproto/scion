FROM ubuntu:14.04
ENV HOME /home/scion
ENV BASE /home/scion/scion.git
WORKDIR /home/scion/scion.git

RUN cd /etc/apt/apt.conf.d/ && rm 01autoremove 01autoremove-kernels 20changelog
# Remove 'essential' packages that we don't need
COPY docker/pkgs_purge_essential.txt $BASE/docker/
RUN echo 'Yes, do as I say!' | bash -c 'DEBIAN_FRONTEND=noninteractive apt-get purge -y --force-yes $(< docker/pkgs_purge_essential.txt)'
# Remove normal packages that we don't need
COPY docker/pkgs_purge.txt $BASE/docker/
RUN bash -c 'DEBIAN_FRONTEND=noninteractive apt-get purge --auto-remove -y $(< docker/pkgs_purge.txt)'

# Pre-install some of the largest indirect dependancies, to speed up rebuild when
# deps.sh changes for any reason.
RUN apt-get update
COPY docker/pkgs_preinstall.txt $BASE/docker/
RUN bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y $(< docker/pkgs_preinstall.txt)'

################################################################################
# Handle installing all dependancies up-front. That way code changes don't cause
# the expensive part of the image build to be re-run.
################################################################################

RUN useradd -s /bin/bash scion
RUN echo "scion ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/scion

# Copy over deps.sh. If it has changed, everything gets rebuilt.
USER scion
COPY deps.sh $BASE/

# Copy over pkgs_debian.txt. If it has changed, then re-run the remaining steps.
COPY pkgs_debian.txt $BASE/
RUN sudo chown -R scion: $HOME
RUN APTARGS=-y ./deps.sh pkgs

# Copy over requirements.txt. If it has changed, then re-run the remaining steps.
COPY requirements.txt $BASE/
RUN sudo chown -R scion: $HOME
RUN ./deps.sh pip

RUN ./deps.sh misc

RUN sudo rm -rf /usr/share/man
# Clean out the cached packages now they're no longer necessary
RUN sudo apt-get clean
RUN sudo du -hsx /

#################################################################################
## All dependancies are now installed, carry on with the rest.
#################################################################################

COPY scion.sh $BASE/

# Pre-build crypto library, so that unrelated code changes don't force a rebuild every time.
COPY lib/crypto/python-tweetnacl-20140309/ $BASE/lib/crypto/python-tweetnacl-20140309/
RUN sudo chown -R scion: $HOME
RUN ./scion.sh init

RUN echo "PATH=$HOME/.local/bin:/usr/share/zookeeper/bin:$PATH" >> ~/.profile
# Now copy over the current branch
COPY . $BASE/
RUN sudo chown -R scion: $HOME
# Build topology files
RUN ./scion.sh topology
# Copy over init.sh:
COPY docker/init.sh $HOME/bin/
# Install basic screen config
COPY docker/screenrc $HOME/.screenrc

# Fix ownership one last time:
RUN sudo chown -R scion: $HOME
# Fix some image problems:
RUN sudo chmod g+s /usr/bin/screen

CMD ["/home/scion/bin/init.sh"]
