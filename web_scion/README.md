## Installation

#### Manual installation

1. Go to `web_scion/`, install the dependencies

    `pip3 install --user -r requirements.txt`

2. Copy the private settings file, update it if necessary

    `cp web_scion/settings/private.dist.py web_scion/settings/private.py`

2. Run migrations

    `./manage.py migrate`

    Optional: test the installation

    `./manage.py test`

3. Populate the database from the topology files

    `python3 ./scripts/reload_data.py`

4. Generate TLS certificates (WARNING: if you overwrite the existing certificates, you won't be able to connect to ADs that still use them)

    `bash ../ad_management/certs/certs.sh gen`

5. Run the server

    `./manage.py runserver`

#### Installing with Docker

1. Build the full SCION image (from the SCION root directory):

    `./docker.sh build`

2. Build and run the web image:

    `./web_scion/docker/run_docker.sh`

#### Using PostgreSQL

By default an SQLite database is used, and it works fine if the number of ADs is relatively small (lower than 100). One can switch to using PostgreSQL for improved performance and flexibility.

1. Install additional system dependencies

    `sudo apt-get install python3-psycopg2`

2. Update the DATABASES hash in `web_scion/settings/private.py` ('ENGINE' must be `django.db.backends.postgresql_psycopg2`)

3. Run the PostgreSQL docker image

    `./scripts/start_postgres_docker.sh`

## Usage

 Open the web panel after starting the test server: `http://localhost:8000/`

 Admin panel is located at `http://localhost:8000/admin` (login: admin, password: admin).

 Don't forget to run the management daemon if you want to manage server elements:

    ./supervisor/supervisor.sh start management_daemon


#### Feature overview

* Topology push/pull

Go to the 'Topology' tab of the AD overview page. You can now click the 'Check topology' button to compare the remote (stored at the AD host) and the local (stored in the web app database) topology. If two topologies are not consistent, you will be given a list of changes between them.  Now you can either push the local topology to the AD host, or pull the remote topology from the AD host and overwrite the local topology.

After the topology is pushed to the AD, the corresponding monitoring daemon is restarted, which might take a few seconds.

* Connecting new ADs and connection requests

Adding new ADs to the network is implemented via the concept of connection requests. Assume you want to create a new AD and to connect it to AD 1. To do that, you open the 'Connection requests' tab of AD 1 and click the 'New request' button. Then you fill the form, providing some information about the prospective AD (purpose, location), including the router (or AD host) details: IP, port. There is an option to specify "external" IP and port if they differ from local values, for example, if the AD host is behind the NAT.

After the connection request is sent, it is listed in two places: on the 'Submitted request' page for the request sender, and on the 'Connection request' tab of AD 1 (the 'Received requests' section). The administrator of AD 1 can now review the submitted request on the latter web page. Then, he can approve or decline the request by clicking the corresponding button. If the request is approved, then the request sender can download the generated package from the 'Submitted request' page. After it, he just needs to upload the package to the AD host, extract it, and run the 'web_scion/scripts/deploy.sh' script, which will execute all essential deployment steps.

AD can also be marked as 'open' (see the `is_open` AD attribute), which means that every sent request is approved automatically.

* Software updates

Software packages are prepared using the `packaging.py` module. Just run it as `python3 ad_management/packaging.py`, and it will create a package and save it in `ad_management/.packages`. The package will also contain some metadata (commit  id, creation date) in a file called META.

After the package is created, you can go to the 'Software updates' tab and click the 'Refresh' button. This will refresh the list of available package versions. Now, you can either install the selected package remotely ('Install the update') or simply download it ('Download the update').

* Two-factor authentication

Enable 2FA by adding this line to the `settings/private.py` file:

```
ENABLED_2FA = TWO_FACTOR_PATCH_ADMIN = True

```

Also update `TWILIO_*` and `TWO_FACTOR_SMS_GATEWAY` variables with proper values.

#### Common problems

If something doesn't work (no element status displayed, topology cannot be retrieved, etc.), do the following:

1. Check that the management daemon is running at the AD host (`./supervisor/supervisor.sh status`).
2. If the AD is deployed on a virtual or remote machine (not on localhost/127.0.0.1), ensure that the management daemon of that AD is listening on the 0.0.0.0 address, and not 127.0.0.1 (check the `[program:management_daemon]` section in `supervisor/supervisord.conf`).
3. Check that the md_host attribute of the AD points to the correct host where the management daemon is deployed. You can check it on the AD administration page (/admin/ad_manager/ad/<AD_ID>/).
4. Check that the web panel can open the TLS connection to the port 9010 of the AD host.
5. Software updates don't work? Check that the corresponding RPC function (`self.send_update`) is registered in the `ManagementDaemon.__init__()` function. Thing to keep in mind: this is a highly experimental feature and should be used with care before additional security reviews are done, otherwise this can result in remote code execution vulnerabilities.

Don't forget to restart the management daemon(s) after any modifications are done to the source code.

#### Code structure

There are two directories (relative to the SCION root directory) that contain all essential components of the testbed management system:

* `ad_management/` -- contains the code of the management daemon (`management_daemon.py`), the updater (`updater.py`) and the packaging (`packaging.py`) modules. Certificates for the web app and the management daemon are also there: check the `certs/` directory.

* `web_scion/` -- contains the web management application (Django web app). All the settings are located in `web_scion/web_scion/settings/`, useful scripts -- under `web_scion/scripts`, the actual web module (views, models) -- under `web_scion/ad_manager`.

#### Current limitations

1. ISD is a foreign key for the AD model, so currently an AD can only belong to a single ISD.
2. All ADs are using the same certificate for authentication (`ad_management/certs/ad.pem`).
