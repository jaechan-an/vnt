#!/bin/bash
rm -rf logs
rm -rf receipts

./reset_db.sh
#cargo run --release -j 4 --bin simulator -- --tables=10 --time=5
##cargo run --bin host -- --src-ip 1.1.1.1 --dst-ip 9.9.9.9
#
#cargo run --release -j 4 --bin host

#cargo clean

cargo run --bin simulator -- --tables=2 --time=2

cargo run --bin host -- --tables=2

cargo run --bin verify

cargo run --bin query_host -- --src1=0 --dst1=1 --src2=1 --dst2=0

cargo run --bin query_verify

