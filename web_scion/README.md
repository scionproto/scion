## Installation

#### Manual installation

1. Go to `web_scion/`, install the dependencies

    `pip3 install --user -r requirements.txt`

2. Copy the private settings file, update it if necessary

    `cp web_scion/settings_private.py.dist web_scion/settings_private.py`

2. Run migrations

    `./manage.py migrate`

    Optional: test the installation

    `./manage.py test`

3. Populate the database from the topology files

    `python3 ./scripts/load_data.py`

4. Run the server

    `./manage.py runserver`

#### Installing with Docker

1. Build the full SCION image (from the SCION root directory):

    `./docker.sh build`

2. Build and run the web image:

    `./web_scion/docker/run_docker.sh`

#### Using PostgreSQL

By default an SQLite database is used. One can switch to using PostgreSQL for improved performance and flexibility.

1. Install additional system dependencies

    `sudo apt-get install python3-psycopg2`

2. Update the DATABASES hash in `web_scion/settings_private.py` ('ENGINE' must be `django.db.backends.postgresql_psycopg2`)

3. Run the PostgreSQL docker image

    `./scripts/start_postgres_docker.sh`

## Usage

 Open the web panel after starting the test server: `http://localhost:8000/`

 Admin panel is located at `http://localhost:8000/admin` (login: admin, password: admin)

 Don't forget to run the management daemon if you want to manage server elements:

    ./supervisor/supervisor.sh start management_daemon

#### Common problems

If something doesn't work (no element status displayed, topology cannot be retrieved, etc.), do the following:

1. Check that the management daemon is running at the AD host (`./supervisor/supervisor.sh status`).
2. If the AD is deployed on a virtual or remote machine (not on localhost/127.0.0.1), ensure that the management daemon of that AD is listening on the 0.0.0.0 address, and not 127.0.0.1 (check section `[program:management_daemon]` in `supervisor/supervisord.conf`).
3. Check that the web panel can open the TLS connection to the port 9010 of the AD host.
4. If software updates don't work, check that 

#### Code structure


