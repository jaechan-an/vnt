#!/bin/bash

# Variables
DB_HOST="localhost"         # Change to your Postgres server address if needed
DB_PORT="5432"              # Default Postgres port
ADMIN_USER="$(whoami)"      # Postgres admin user (for mac)
#ADMIN_USER="postgres"       # Postgres admin user (for linux)
ADMIN_PASSWORD="postgres"   # Admin password

PROJECT="vns"
SQL_DIR="sql"
RESET_SQL="${SQL_DIR}/reset.sql"
INIT_SQL="${SQL_DIR}/init.sql"

# Step 1: Reset the database (drop/create database, setup user, etc.)
export PGPASSWORD=${ADMIN_PASSWORD}
psql -U ${ADMIN_USER} -d postgres -h ${DB_HOST} -p ${DB_PORT} -f "${RESET_SQL}"

# Step 2: Connect to the new database and initialize tables
export PGPASSWORD=${PROJECT}
psql -U ${PROJECT} -d ${PROJECT} -h ${DB_HOST} -p ${DB_PORT} -f "${INIT_SQL}"

# Check for errors and clean up
if [ $? -eq 0 ]; then
  echo "Database setup completed successfully!"
else
  echo "Error: Failed to execute database setup."
  exit 2
fi
