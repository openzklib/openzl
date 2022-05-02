# OpenZL

![OpenZL](https://user-images.githubusercontent.com/720571/166172246-bf37c77e-51e2-4176-8195-70a9361319d7.svg)

## Overview


## OpenZL Design

## OpenZL Goals and Non-Goals

**Goals:**
* A *production ready* and *proof-system agnostic* ZK library for blockchain applications (support [arkworks/groth16](https://github.com/arkworks-rs/groth16), [zk-garage/plonk](https://github.com/zk-garage/plonk), [microsoft/nova](https://github.com/microsoft/Nova))
* **ZIR**: A shallow embedded circuit DSL in Rust that can rule out some common errors using Rust's type systems
* Common gadgets such as hashing, commitment, accumulators in **ZIR**.
* Able to compile both prover and verifier to standard WASM and substrate flavored WASMI
* Tutorials support substrate ecosystem zero-knowledge proof applications

**Non-Goals:**
* Build high-level language like Circom/Cairo (Would love to see someone else build high level language compiled to ZIR though)
* Build "yet another plonk" 
* Create new fragmentation in ZK tooling space

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
