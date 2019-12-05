FROM scion_base_build:latest

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
    python3-pip python3-setuptools python3-wheel python3-dev python3-nose libssl-dev libffi-dev jq capnproto\
    && apt-get clean

COPY env/pip3/requirements.txt requirements.txt
RUN pip3 install -r ./requirements.txt
RUN rm ./requirements.txt
