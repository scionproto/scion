#!/bin/bash

# Creds
USER_NAME=scionuser
USER_PASS=scionpass
DB_NAME=sciondb

# Stop previous container
sudo docker kill scion-postgres
sudo docker rm scion-postgres

# Run the new container
POSTGRES_PASS=postgres
sudo docker run --name scion-postgres -e POSTGRES_PASSWORD=$POSTGRES_PASS -d -p 5432:5432 postgres
sleep 3

# Create db
sudo docker exec scion-postgres createdb -U postgres $DB_NAME

# Add a user
CREATE_SQL="
  CREATE ROLE $USER_NAME WITH ENCRYPTED PASSWORD '$USER_PASS';
  GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $USER_NAME;
  ALTER ROLE $USER_NAME WITH LOGIN CREATEDB;
"
echo "$CREATE_SQL" | PGPASSWORD=$POSTGRES_PASS psql -U postgres -h localhost

# Run migrations
python3 ../manage.py migrate

# Seed the db
python3 ../scripts/reload_data.py 

