### Manual installation

1. Go to `web_scion/`, install dependencies

    `sudo pip3 --user install -r requirements.txt`

2. Copy and update the private settings file

    `cp web_scion/settings_private.py.dist web_scion/settings_private.py`

2. Run migrations

    `./manage.py migrate ad_manager`

    Optional: test the installation

    `./manage.py test`

3. Populate the database from the topology files

    `PYTHONPATH=.. python3 ./scripts/load_data.py`

4. Run the server

    `./manage.py runserver`

5. Open the web panel: http://localhost:8000/

   Admin panel is located at http://localhost:8000/admin (login: admin, password: admin)

   Don't forget to run the monitoring daemon if you want to manage server elements:

    `./supervisor/supervisor.sh start monitoring_daemon`

### Docker

1. Build the full SCION image (from the SCION root directory):

    `./docker.sh build`
    
2. Build and run the web image:

    `./web_scion/docker/run_docker.sh`
