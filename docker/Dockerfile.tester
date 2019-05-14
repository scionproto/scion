FROM scion:latest

USER root
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y libcap2-bin net-tools iputils-ping iproute2 && apt-get clean

COPY --from=scion_app_builder:latest $BASE/bin/* $BASE/bin/
RUN cp $BASE/docker/tester.sh $BASE
RUN chmod +x tester.sh
CMD tail -f /dev/null
