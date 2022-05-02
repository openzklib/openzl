# openzl

![openzl](https://user-images.githubusercontent.com/720571/166172246-bf37c77e-51e2-4176-8195-70a9361319d7.svg)

## Overview

Openzl is an open-sourced library that helps practioners (especially in Web3 space) to deploy secure, high performance zero-knowledge proof code in production. It tries to bridge the big gap in the current zero-knowledge proof tooling space: the lower level proof-system and the higher level applications. More specifically, many developers today want to leverage zero-knowledge proof system to build powerful protocols like ZCash or Manta. However, they are facing two un-ideal choices; first, building the protocol using high-level languages like [Circom](https://docs.circom.io/)/[Cairo](https://www.cairo-lang.org/) loses many performance optimization opportunities, second, building the protocol directly using libraries like [arkworks/groth16](https://github.com/arkworks-rs/groth16), [zk-garage/plonk](https://github.com/zk-garage/plonk), [microsoft/nova](https://github.com/microsoft/Nova) requires expertise in cryptography and is very error-prone. Also, the zero-knowledge proof system is a moving target, there has been new, and "better" proof systems coming out every 2~3 years ([BCTV](https://eprint.iacr.org/2013/879.pdf) -> [Groth16](https://eprint.iacr.org/2016/260.pdf) -> [Plonk](https://eprint.iacr.org/2019/953) -> [Nova](https://eprint.iacr.org/2021/370)). Openzl tries to solve this problem by building a flexible, proof-system agnostic, and extensible libraries for Web3 practioners.  

## Openzl Design

## Openzl Goals and Non-Goals

**Goals:**
* A *production ready* and *proof-system agnostic* ZK library for blockchain applications (support [arkworks/groth16](https://github.com/arkworks-rs/groth16), [zk-garage/plonk](https://github.com/zk-garage/plonk), [microsoft/nova](https://github.com/microsoft/Nova)).
* `eclair`: A shallow embedded circuit DSL in Rust that can rule out some common errors using Rust's type systems.
* Common gadgets such as hashing, commitment, accumulators in `eclair`.
* Able to compile both prover and verifier to standard WASM and substrate flavored WASMI.
* Tutorials support substrate ecosystem zero-knowledge proof applications.

**Non-Goals:**
* Build high-level language like Circom/Cairo (Would love to see someone else build high level language compiled to ZIR though).
* Build "yet another plonk". 
* Create new fragmentation in ZK tooling space.

## OpenZL Roadmap and Milestones
* Milestone 1 (Prototype): July, 2022

* Milestone 2 (Feature Complete): Sep, 2022

* Milestone 3 (Audit): Nov. 2022
  Potential auditors: ABDK, Least Authority, Trail of Bits

## Open-Sourced Contribution
OpenZL will be closely curated by Manta Team and will **NOT** accept open-sourced contribution unless communicated with Manta Team.

## OpenZL Oversee Committee
* Shumo Chu (Co-founder, Manta Network)
* Luke Pearson (Research Partner, Polychain Capital)
* Bryan Chen (CTO, Acala Network)

Funding and spendings will be managed in a 2/3 multisig.
