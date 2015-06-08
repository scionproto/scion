To run the server:

1. Install dependencies

   sudo pip3 install -r requirements.txt

2. Copy and update the private settings file:

   cp web_scion/settings_private.py.dist web_scion/settings_private.py

2. Run migrations

  ./manage.py migrate

Optional: test the installation

  ./manage.py test

3. Populate the database from the topology files:

  python3 ./scripts/load_data.py

4. Run the server

  ./manage.py runserver

5. Open the web admin: http://localhost:8000/

   Admin panel is located at http://localhost:8000/admin (login: admin, password: admin)

   Don't forget to run the monitoring daemon:

   ./supervisor/supervisor.sh start monitoring_daemon

