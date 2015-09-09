FROM scion:latest

WORKDIR ./web_scion/

RUN pip3 install --user -r requirements.txt

RUN cp ./web_scion/settings/private.dist.py ./web_scion/settings/private.py

RUN ./manage.py migrate

RUN python3 scripts/reload_data.py

EXPOSE 8000

WORKDIR /home/scion/scion.git

USER scion

ENV PATH ~/.local/bin:$PATH

ENTRYPOINT /bin/bash ./supervisor/supervisor.sh reload \
    && /bin/bash ./supervisor/supervisor.sh start management_daemon \
    && python3 web_scion/manage.py runserver 0.0.0.0:8000
