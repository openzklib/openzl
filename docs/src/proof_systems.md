# Proof System Plugins

One of the goals of OpenZL is to provide great flexibility with respect to ZK proof systems. Developers should focus on the business logic of their application without committing to a particular ZK proof system. ECLAIR makes this possible. 

ECLAIR code describes computation in general terms that make minimal assumptions about the environment where that code will be executed. This is ideal in the early stage of production when we need a circuit description that conforms to our spec. But at some point we do have to turn words into actions and use ECLAIR code to create ZKPs. This is where plugins come in.

Recall what it means to write a proof system plugin for ECLAIR circuits: One must define a compiler type `COM` and implement the traits that specify how `COM` generates constraints for operations like addition, assertion, *etc*. (If that sounds unfamiliar, you may wish to first read more about the [`COM` abstraction](native_nonnative.md) and the [ECLAIR Standard Library](/std/eclair_std_lib.md).)

A proof system plugin provides the low-level instructions for variable allocation and constraint generation in a specific ZK proof system. The plugin defines how ECLAIR code is compiled to constraints and, ultimately, used to generate ZKPs.

As a technical note, it is not quite correct to say that a plugin targets a specific ZK proof system; rather, a plugin targets a specific *implementation* of a ZK proof system. For example, there is no such thing as a "Groth16 plugin"; rather, there is a plugin for the Arkworks *implementation* Ark-Groth16.

OpenZL currently has ArkGroth16 and Plonky2 proof system plugins; more are coming soon!