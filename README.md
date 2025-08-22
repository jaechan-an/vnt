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

## Quick Start

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

### Executing the Project Locally in Development Mode

During development, faster iteration upon code changes can be achieved by leveraging [dev-mode], we strongly suggest activating it during your early development phase. Furthermore, you might want to get insights into the execution statistics of your project, and this can be achieved by specifying the environment variable `RUST_LOG="[executor]=info"` before running your project.

Put together, the command to run your project in development mode while getting execution statistics is:

```bash
RUST_LOG="[executor]=info" RISC0_DEV_MODE=1 cargo run
```

### Running Proofs Remotely on Bonsai

_Note: The Bonsai proving service is still in early Alpha; an API key is
required for access. [Click here to request access][bonsai access]._

If you have access to the URL and API key to Bonsai you can run your proofs
remotely. To prove in Bonsai mode, invoke `cargo run` with two additional
environment variables:

```bash
BONSAI_API_KEY="YOUR_API_KEY" BONSAI_API_URL="BONSAI_URL" cargo run
```

## How to Create a Project Based on This Template

Search this template for the string `TODO`, and make the necessary changes to
implement the required feature described by the `TODO` comment. Some of these
changes will be complex, and so we have a number of instructional resources to
assist you in learning how to write your own code for the RISC Zero zkVM:

- The [RISC Zero Developer Docs][dev-docs] is a great place to get started.
- Example projects are available in the [examples folder][examples] of
  [`risc0`][risc0-repo] repository.
- Reference documentation is available at [https://docs.rs][docs.rs], including
  [`risc0-zkvm`][risc0-zkvm], [`cargo-risczero`][cargo-risczero],
  [`risc0-build`][risc0-build], and [others][crates].

## Directory Structure

It is possible to organize the files for these components in various ways.
However, in this starter template we use a standard directory structure for zkVM
applications, which we think is a good starting point for your applications.

```text
project_name
├── Cargo.toml
├── host
│   ├── Cargo.toml
│   └── src
│       └── main.rs                    <-- [Host code goes here]
└── methods
    ├── Cargo.toml
    ├── build.rs
    ├── guest
    │   ├── Cargo.toml
    │   └── src
    │       └── method_name.rs         <-- [Guest code goes here]
    └── src
        └── lib.rs
```

## Video Tutorial

For a walk-through of how to build with this template, check out this [excerpt
from our workshop at ZK HACK III][zkhack-iii].

## Questions, Feedback, and Collaborations

We'd love to hear from you on [Discord][discord] or [Twitter][twitter].

[bonsai access]: https://bonsai.xyz/apply
[cargo-risczero]: https://docs.rs/cargo-risczero
[crates]: https://github.com/risc0/risc0/blob/main/README.md#rust-binaries
[dev-docs]: https://dev.risczero.com
[dev-mode]: https://dev.risczero.com/api/generating-proofs/dev-mode
[discord]: https://discord.gg/risczero
[docs.rs]: https://docs.rs/releases/search?query=risc0
[examples]: https://github.com/risc0/risc0/tree/main/examples
[risc0-build]: https://docs.rs/risc0-build
[risc0-repo]: https://www.github.com/risc0/risc0
[risc0-zkvm]: https://docs.rs/risc0-zkvm
[rust-toolchain]: rust-toolchain.toml
[rustup]: https://rustup.rs
[twitter]: https://twitter.com/risczero
[zkhack-iii]: https://www.youtube.com/watch?v=Yg_BGqj_6lg&list=PLcPzhUaCxlCgig7ofeARMPwQ8vbuD6hC5&index=5
[zkvm-overview]: https://dev.risczero.com/zkvm
# vnt
