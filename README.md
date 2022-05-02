# OpenZL

![OpenZL](https://user-images.githubusercontent.com/720571/166172246-bf37c77e-51e2-4176-8195-70a9361319d7.svg)

## Overview


## OpenZL Design

## OpenZL Goals and Non-Goals
**Goals:**
* build a proof-system agnostic ZK library for blockchain production (support [arkworks/groth16](https://github.com/arkworks-rs/groth16), [zk-garage/plonk](https://github.com/zk-garage/plonk), microsoft/nova)
* build a shallow embedded circuit DSL in Rust that can rule out some common errors using Rust's type systems
* build common gadgets in this shallow embedded DSL
* able to compile both prover and verifier to standard WASM and WASMI
* support substrate ecosystem zero-knowledge proof development

**Non-Goals:**
* build high-level language like Circom/Cairo
* build "yet another plonk" and create new fragmentation in ZK tooling space

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
The funding will be managed in a 2/3 multisig.
