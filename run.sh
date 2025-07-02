#!/bin/bash
./reset_db.sh
#cargo run --release -j 4 --bin simulator -- --tables=10 --time=5
##cargo run --bin host -- --src-ip 1.1.1.1 --dst-ip 9.9.9.9
#
#cargo run --release -j 4 --bin host

#cargo clean

cargo run -j 4 --bin simulator -- --tables=10 --time=600 &

cargo run -j 4 --bin host &
sleep 120

cargo run -j 4 --bin host &
sleep 120

cargo run -j 4 --bin host &
sleep 120

cargo run -j 4 --bin host &
sleep 120

cargo run -j 4 --bin host
