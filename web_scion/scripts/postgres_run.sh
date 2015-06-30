#!/bin/bash
set -e

SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd $SCRIPT_DIR

# Creds
USER_NAME=scionuser
USER_PASS=scionpass
DB_NAME=sciondb

# Stop previous container
sudo docker kill scion-postgres || true
sudo docker rm scion-postgres || true

# Run the new container
POSTGRES_PASS=postgres
sudo docker run --name scion-postgres -e POSTGRES_PASSWORD=$POSTGRES_PASS -d -p 5432:5432 postgres
sleep 5

# Create db
sudo docker exec scion-postgres createdb -U postgres $DB_NAME

# Add a user
CREATE_SQL="
  CREATE ROLE $USER_NAME WITH ENCRYPTED PASSWORD '$USER_PASS';
  GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $USER_NAME;
  ALTER ROLE $USER_NAME WITH LOGIN CREATEDB;
"
sudo docker exec scion-postgres psql -U postgres -h localhost -c "$CREATE_SQL"

# Run migrations
python3 ../manage.py migrate

# Seed the db
python3 ../scripts/reload_data.py

