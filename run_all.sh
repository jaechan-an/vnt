#!/bin/bash
rm -rf exp
mkdir -p exp

# Number of tables is the number of routers in the netflow simulation.
# Number of records is the total number of records in the simulation.
# Example: 4 tables, 1000 records means 4 routers with a total of 1000 records.

NUM_TABLES=4
NUM_RECORDS_ARRAY=(50 100 500 1000 2000 3000)
#NUM_RECORDS_ARRAY=(20)

RELEASE_MODE=1

if [ "${RELEASE_MODE}" -eq 1 ]; then
  # DEV_MODE=0
  RELEASE="--release"
else
  BUILD_MODE=""
  RELEASE=""
fi

set -e

for NUM_RECORDS in "${NUM_RECORDS_ARRAY[@]}"; do
  echo "Running simulation with ${NUM_TABLES} tables and ${NUM_RECORDS} records..."

  ./reset_db.sh

  rm -rf logs
  rm -rf proofs
  mkdir -p exp/${NUM_RECORDS}

  # Run initial inserts to the tables
  cargo run ${RELEASE} --bin simulator -- --tables=${NUM_TABLES} --records=${NUM_RECORDS}

  sleep 5

  cargo run ${RELEASE} --bin host -- --tables=${NUM_TABLES}

  cargo run ${RELEASE} --bin verify

  # Run updates to the tables
  cargo run ${RELEASE} --bin simulator -- --tables=${NUM_TABLES} --records=${NUM_RECORDS} --update-only

  sleep 5

  cargo run ${RELEASE} --bin host -- --tables=${NUM_TABLES}

  cargo run ${RELEASE} --bin verify

  # sleep 5

  # RISC0_DEV_MODE=${DEV_MODE} cargo run ${RELEASE} --bin query_host -- --tables=${NUM_TABLES}

  # RISC0_DEV_MODE=${DEV_MODE} cargo run ${RELEASE} --bin query_verify

  cp -r logs exp/${NUM_RECORDS}/logs
  cp -r proofs exp/${NUM_RECORDS}/proofs
done

