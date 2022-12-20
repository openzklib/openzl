# Proof System Plugins

One of the goals of OpenZL is to provide great flexibility with respect to ZK proof systems. Developers should focus on the business logic of their application without committing to a particular ZK proof system. ECLAIR makes this possible. 

ECLAIR code describes computation in general terms that make minimal assumptions about the environment where that code will be executed. This is ideal in the early stage of production when we need a circuit description that conforms to our spec. But at some point we do have to turn words into actions and use ECLAIR code to create ZKPs. This is where plugins come in.

A proof system plugin provides the low-level instructions for variable allocation and constraint generation in a specific ZK proof system. The plugin defines how ECLAIR code is compiled to constraints and, ultimately, used to generate ZKPs.

As a technical note, it is not quite correct to say that a plugin targets a specific ZK proof system, but rather a specific *implementation* of a ZK proof system. For example, there is no such thing as a "Groth16 plugin"; rather, there is a plugin for the Arkworks *implementation* Ark-Groth16.