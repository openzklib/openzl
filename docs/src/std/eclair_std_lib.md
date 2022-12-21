# ECLAIR Standard Library

We explained in the previous section that ECLAIR achieves compatibility with various proof systems through its `COM` abstraction, which regards each ZK proving system as its own computational environment. ECLAIR makes minimal assumptions on the inner workings of each computational environment in an attempt to stay general enough to target a wide variety of ZK proving systems.

ECLAIR does, however, include a standard library of traits and types that will be relevant to nearly all `COM` types. We model this ECLAIR Standard Library on the Rust Standard Library. Whenever possible, ECLAIR uses the same API as Rust, with minimal changes to accommodate the `COM` abstraction.

Like the Rust standard library, ECLAIR's standard library is not strictly required; ECLAIR can handle compiler types that for whatever reason do not include implementations of the standard library traits. However, common compiler types will have implementations of most standard library traits, if not all of them.

We recommend reading through this chapter as a way to familiarize oneself with common patterns in ECLAIR. Most readers will be familiar with the Rust standard library and can ease their way into the `COM` abstraction by comparing ECLAIR's standard library traits to their counterparts in the Rust standard library. (The [Bool](bool.md) and [Num](num.md) sections are not so Rust-like, but the [Cmp](cmp.md) and [Ops](ops.md) sections are.)