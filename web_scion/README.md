To run the server:

1. Install dependencies and test the installation

  a) Install web app dependencies (Django, etc.)

  sudo pip3 install -r requirements.txt

  b) Run tests

  ./manage.py test

2. Run migrations

  ./manage.py migrate

3. Populate the database from the topology files:

  python3 ./scripts/load_data.py

4. Run the server

  ./manage.py runserver

5. Open the web admin: http://localhost:8000/
   
   Admin panel is located at http://localhost:8000/admin (login: admin, password: admin)

   Don't forget to run the monitoring daemon:

   ./supervisor/supervisor.sh start monitoring_daemon

