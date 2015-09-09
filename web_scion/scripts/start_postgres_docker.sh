#!/bin/bash
set -e

SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd $SCRIPT_DIR

# Creds
USER_NAME=scionuser
USER_PASS=scionpass
DB_NAME=sciondb

CONTAINER_PORT=5432

# Stop previous container
sudo docker kill scion-postgres &> /dev/null || true
sudo docker rm scion-postgres &> /dev/null || true

# Run the new container
echo "Container id:"
POSTGRES_PASS=postgres
sudo docker run --name scion-postgres -e POSTGRES_PASSWORD=$POSTGRES_PASS -d -p $CONTAINER_PORT:5432 postgres
echo 'Waiting while the database server is up...'
sleep 5

# Create db
echo 'Creating the database...'
sudo docker exec scion-postgres createdb -U postgres $DB_NAME

# Add a user
CREATE_SQL="
  CREATE ROLE $USER_NAME WITH ENCRYPTED PASSWORD '$USER_PASS';
  GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $USER_NAME;
  ALTER ROLE $USER_NAME WITH LOGIN CREATEDB;
"
sudo docker exec scion-postgres psql -U postgres -h localhost -c "$CREATE_SQL"

# Run migrations
echo 'Running migrations...'
python3 ../manage.py migrate

# Seed the db
python3 ../scripts/reload_data.py

echo "Container was started at 127.0.0.1:$CONTAINER_PORT"
