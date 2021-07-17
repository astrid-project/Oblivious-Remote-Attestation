ASTRID Oblivious Remote Attestation

This repository contains the source code of the final release of the Configuration Integrity Verification (CIV) component that runs on the VF execution environments (Provers) and on the Attestation Service as part of the ASTRID orchestration framework (Verifier). Both features of Attestation by Quote and Attestation by Proof have been implemented.

To aid in deployment, the repo contains the necessary configuration files and documentation for instantiating the attestation agent as a container instance that can be directly loaded in the deployed VF. It also contains the implementation of all APIs and Kafka interfaces for communicating with the other ASTRID components, as described in Deliverable "D3.4 - Final Release of the Algorithms for the Detection and Management of Vulnerabilities, Threats and Anomalies". 

ARCHITECTURE

Once the containers are deployed as part of the VF execution environments and the Attestation Services, as Verifiers, part of the ASTRID orchestration framework, the interaction of attestation related events and data takes place through the Kafka communication bus of the ASTRID Context Broker. Furthermore, REST APIs have been provided for (re-) configuring the VF attestation agents, when needed, by the CB Manager.

DEPENDENCIES

IBM TSS
IBM TPM or a Hardware TPM (Not tested!)
OpenSSL (required by IBM TSS)
Build
