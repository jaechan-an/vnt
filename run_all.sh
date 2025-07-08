#!/bin/bash
rm -rf exp
mkdir -p exp

NUM_TABLES=4
NUM_RECORDS_ARRAY=(50 100 500 1000 2000 3000 4000 5000)

for NUM_RECORDS in "${NUM_RECORDS_ARRAY[@]}"; do
  echo "Running simulation with ${NUM_TABLES} tables and ${NUM_RECORDS} records..."

  ./reset_db.sh

  rm -rf logs
  rm -rf receipts

  cargo run --bin simulator -- --tables=${NUM_TABLES} --records=${NUM_RECORDS}

  cargo run --bin host -- --tables=${NUM_TABLES}

  cargo run --bin verify

  cargo run --bin query_host -- --tables=${NUM_TABLES}

  cargo run --bin query_verify

  cp -r logs exp/${NUM_RECORDS}/logs
  cp -r receipts exp/${NUM_RECORDS}/receipts
done
