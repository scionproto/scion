FROM ubuntu:16.04
ENV HOME /home/scion
ENV BASE /home/scion/go/src/github.com/netsec-ethz/scion

WORKDIR $BASE

# Speed up a lot of the building
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y eatmydata
RUN ln -s /usr/bin/eatmydata /usr/local/bin/apt-get
RUN ln -s /usr/bin/eatmydata /usr/local/bin/dpkg

# Remove 'essential' packages that we don't need
COPY docker/pkgs_purge_essential.txt $BASE/docker/
RUN echo 'Yes, do as I say!' | bash -c 'DEBIAN_FRONTEND=noninteractive apt-get purge -y --allow-remove-essential $(< docker/pkgs_purge_essential.txt)'
# Remove normal packages that we don't need
COPY docker/pkgs_purge.txt $BASE/docker/
RUN bash -c 'DEBIAN_FRONTEND=noninteractive apt-get purge --auto-remove -y $(< docker/pkgs_purge.txt)'
RUN bash -c 'DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge'

# Pre-install some of the largest indirect dependencies, to speed up rebuild when
# deps.sh changes for any reason.
COPY docker/pkgs_preinstall.txt $BASE/docker/
RUN bash -c 'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y $(< docker/pkgs_preinstall.txt)'

################################################################################
# Handle installing all dependencies up-front. That way code changes don't cause
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
RUN sudo apt-get update && APTARGS=-y ./deps.sh pkgs

# Copy over requirements.txt. If it has changed, then re-run the remaining steps.
COPY requirements.txt $BASE/
RUN sudo chown -R scion: $HOME
RUN ./deps.sh zlog
RUN ./deps.sh misc
RUN ./deps.sh pip

RUN sudo rm -rf /usr/share/man
# Clean out the cached packages now they're no longer necessary
RUN sudo apt-get clean
RUN sudo du -hsx /

#################################################################################
## All dependencies are now installed, carry on with the rest.
#################################################################################

# Now copy over the current branch
COPY . $BASE/
RUN sudo chown -R scion: $HOME
# Build topology files
RUN ./scion.sh topology
# Install bash config
COPY docker/profile $HOME/.profile
# Install basic screen config
COPY docker/screenrc $HOME/.screenrc
# Install ZK config
COPY docker/zoo.cfg /etc/zookeeper/conf/

# Fix ownership one last time:
RUN sudo chown -R scion: $HOME
# Fix some image problems:
RUN sudo chmod g+s /usr/bin/screen

CMD []
ENTRYPOINT ["/bin/bash", "-l"]
