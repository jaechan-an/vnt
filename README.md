# Verifiable Network Telemetry

This project presents a purely software-based approach to verifiable network telemetry using zero-knowledge proofs (ZKPs). It enables third-party verification of network performance metrics—such as packet loss or flow counts—without revealing sensitive telemetry logs. Our system addresses two core challenges: (1) ensuring data integrity via lightweight, per-router hash commitments, and (2) preserving confidentiality by generating ZKPs that attest to correct computation over committed data. Built on the RISC Zero ZKP framework, the design could support arbitrary query logic and decouples aggregation from query processing for scalable, off-path computation. This repository includes our full prototype, written in Rust, with evaluation scripts, aggregation logic, and guest code for generating verifiable proofs.

**[Paper Link](https://drive.google.com/file/d/1fyqbl7lSLHFslbywCCzuXPx5WHf_FEtU/view?usp=sharing)**

## Prerequisites
- [RISC Zero](https://risczero.com/)
- [Zero-knowledge Proofs - Youtube](https://youtu.be/9hJNw2i1dL4?si=edrxklIvcf84ZN4C)
- [Rust](https://www.rust-lang.org/)

## Directory Structure

This repository is structured to separate concerns between data simulation, aggregation, query handling, and zero-knowledge proof generation. Below is an overview of the main components:

- `core/`: Contains shared utilities and data structures, including NetFlow log definitions and Merkle tree operations, used across both aggregation and query phases.
- `host/`: Responsible for executing the aggregation phase and generating zero-knowledge proofs based on the logic defined in `methods/`.
- `methods/`: Defines the aggregation logic executed within the zkVM. The `host/` invokes this logic to generate verifiable proofs.
- `query_host/`: Handles ZKP proof generation for client queries, operating over the committed aggregated dataset.
- `query_methods/`: Encapsulates query logic (e.g., sum, average) to be run inside the zkVM.
- `query_verify/`: Provides verification logic for validating proofs generated during the query phase.
- `simulator/`: Simulates NetFlow data by generating raw logs that are later aggregated by the `host/` during the proof generation process.

## Installation
Currently only supports `Ubuntu 20.04`.
```bash
sudo apt update
sudo apt upgrade
sudo apt install postgresql postgresql-contrib
sudo apt-get install libpq-dev
sudo service postgresql start

# Install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Risc Zero (https://dev.risczero.com/api/zkvm/install)
curl -L https://risczero.com/install | bash
rzup install

# Setup Postgres
sudo -i -u postgres psql
ALTER USER postgres PASSWORD 'postgres'
```

## Quick Start

**I suggest checking simulator -> host -> method -> verify -> query_host -> query_guest -> query_verify in the given order.**

You must have the followings installed:
postgres, rust, RISC-zero

```bash
# In the project directory
./run_all.sh # Runs all the experiments. Checkout the script.
```

To run each module one-by-one,
```bash
# Reset the database
./reset_db.sh

# Run Simulator
cargo run --release --bin simulator -- --tables=${NUM_TABLES} --records=${NUM_RECORDS}

# Run host (aggregation phase)
cargo run --release --bin host -- --tables=${NUM_TABLES}

# Run host verification (verify the aggregation proof)
cargo run --release --bin verify

# Run query_host (query logic phase)
cargo run --release --bin query_host -- --tables=${NUM_TABLES}

# Run query_verification (verify the query proof)
cargo run --release --bin query_verify
```

We have a logging system which is written into the `logs` directory.
The receipts will be inside the `receipts` directory by default.

