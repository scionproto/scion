### Manual installation

1. Go to `web_scion/`, install the dependencies

    `sudo pip3 --user install -r requirements.txt`

2. Copy the private settings file, update it if necessary

    `cp web_scion/settings_private.py.dist web_scion/settings_private.py`

2. Run migrations

    `./manage.py migrate`

    Optional: test the installation

    `./manage.py test`

3. Populate the database from the topology files

    `PYTHONPATH=.. python3 ./scripts/load_data.py`

4. Run the server

    `./manage.py runserver`

### Installing with Docker

1. Build the full SCION image (from the SCION root directory):

    `./docker.sh build`
    
2. Build and run the web image:

    `./web_scion/docker/run_docker.sh`

## Usage

 Open the web panel: `http://localhost:8000/`

 Admin panel is located at `http://localhost:8000/admin` (login: admin, password: admin)

 Don't forget to run the monitoring daemon if you want to manage server elements:

    `./supervisor/supervisor.sh start monitoring_daemon`
