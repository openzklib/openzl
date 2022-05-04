# openzl

![openzl](https://user-images.githubusercontent.com/720571/166172246-bf37c77e-51e2-4176-8195-70a9361319d7.svg)

## Overview

OpenZL is an open-source library that helps practioners (especially in Web3 space) to deploy secure, high performance zero-knowledge proof code in production. It tries to bridge the big gap in the current zero-knowledge proof tooling space: lower level proof-systems and higher level applications. More specifically, many developers today want to leverage zero-knowledge proof systems to build powerful protocols like ZCash or Manta. However, they are facing two less than ideal choices; first, building a protocol using high-level languages like [Circom](https://docs.circom.io) or [Cairo](https://www.cairo-lang.org) loses many performance optimization opportunities, and second, building the protocol directly using libraries like [arkworks/groth16](https://github.com/arkworks-rs/groth16), [zk-garage/plonk](https://github.com/zk-garage/plonk), or [microsoft/nova](https://github.com/microsoft/Nova) requires expertise in cryptography and can be very error-prone. Also, zero-knowledge proof systems are a moving target. There have been many new, and "better" proof systems coming out every 2-3 years ([BCTV](https://eprint.iacr.org/2013/879.pdf) -> [Groth16](https://eprint.iacr.org/2016/260.pdf) -> [Plonk](https://eprint.iacr.org/2019/953) -> [Nova](https://eprint.iacr.org/2021/370)). OpenZL tries to solve this problem by building flexible, proof-system agnostic, and extensible libraries for Web3 practioners.  

## OpenZL Goals and Non-Goals

### Goals

* A *production ready* and *proof-system agnostic* ZK library for blockchain applications (support [arkworks/groth16](https://github.com/arkworks-rs/groth16), [zk-garage/plonk](https://github.com/zk-garage/plonk), [microsoft/nova](https://github.com/microsoft/Nova)).
* `eclair` (**E**mbedded **C**ircuit **L**anguage **A**nd **I**ntermediate **R**epresentation): A shallow embedded circuit DSL in Rust that can rule out some common errors using Rust's type systems and still allow for optimizing circuits.
* Common gadgets such as hash functions, commitment schemes, accumulators, and more in `eclair`.
* Able to compile both prover and verifier to standard WASM and substrate flavored WASMI.
* Tutorials to support substrate ecosystem zero-knowledge proof applications.

### Non-Goals

* Build high-level languages like Circom and Cairo (would love to see someone else build high-level languages that compile to `eclair` though).
* Build "yet another PLONK". 
* Create more fragmentation in ZK tooling space.

## OpenZL Roadmap and Milestones

* Milestone 1 (Prototype): July, 2022
* Milestone 2 (Feature Complete): Sep, 2022
* Milestone 3 (Audit): Nov. 2022
  Potential auditors: ABDK, Least Authority, Trail of Bits

## Open-Source Contributions

OpenZL will be closely curated by Manta Team and will **NOT** accept open-source contributions unless communicated with Manta Team.

## OpenZL Oversight Committee

* Shumo Chu (Co-founder, Manta Network)
* Luke Pearson (Research Partner, Polychain Capital)
* Bryan Chen (CTO, Acala Network)

Funding and spendings will be managed in a 2/3 multisig.

