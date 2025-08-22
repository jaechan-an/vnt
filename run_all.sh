#!/bin/bash
rm -rf exp
mkdir -p exp

# Number of tables is the number of routers in the netflow simulation.
# Number of records is the total number of records in the simulation.
# Example: 4 tables, 1000 records means 4 routers with a total of 1000 records.

NUM_TABLES=4
NUM_RECORDS_ARRAY=(50 100 500 1000 2000 3000)

for NUM_RECORDS in "${NUM_RECORDS_ARRAY[@]}"; do
  echo "Running simulation with ${NUM_TABLES} tables and ${NUM_RECORDS} records..."

  ./reset_db.sh

  rm -rf logs
  rm -rf receipts
  mkdir -p exp/${NUM_RECORDS}

  cargo run --release --bin simulator -- --tables=${NUM_TABLES} --records=${NUM_RECORDS}

  RISC0_DEV_MODE=0 cargo run --release --bin host -- --tables=${NUM_TABLES}

  RISC0_DEV_MODE=0 cargo run --release --bin verify

  RISC0_DEV_MODE=0 cargo run --release --bin query_host -- --tables=${NUM_TABLES}

  RISC0_DEV_MODE=0 cargo run --release --bin query_verify

  cp -r logs exp/${NUM_RECORDS}/logs
  cp -r receipts exp/${NUM_RECORDS}/receipts
done
