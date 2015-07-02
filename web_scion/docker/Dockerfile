FROM scion:latest

WORKDIR ./web_scion/

RUN pip3 install --user -r requirements.txt

RUN cp ./web_scion/settings_private.dist.py ./web_scion/settings_private.py

RUN ./manage.py migrate

RUN python3 scripts/reload_data.py

EXPOSE 8000

USER scion

ENV PATH ~/.local/bin:$PATH

CMD ../supervisor/supervisor.sh reload \
    && ../supervisor/supervisor.sh start monitoring_daemon \ 
    && python3 manage.py runserver 0.0.0.0:8000
