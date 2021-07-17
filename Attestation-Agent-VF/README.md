# Attesation Agent running at the VF as the Prover

This archive contains the containerized version of the remote prover's side, as part of the deployed VF, that can be requested by the Attestation Service to initiate
a configuration integrity process during run-time. The prover runs at the VF and exposes REST APIs and Kafka topics (as part of the Local Communication and Management Framework) 
to allow the Orchestrator (and other ASTRID components) to interact with it.

## Contents

- `include`: Header files
- `libs`: Dependencies
- `src`: Source files
- `CMakeLists.txt`: Project file
- `docker-compose.yml`: Docker compose file
- `DockerFile`: Build file for containerized execution environment
- `main.cpp`: Application that performs secure enrollment
- `vmSigningKeyPrivate`: Private part of the prover device's signing key (endorsement key)
- `vmSigningKeyPublic`: Public part of the prover device's signing key (endorsement key)
- `orchestratorSigningKeyPublic`: Public part of the Orchestrator's signing key (endorsement key)
- `run.sh`: Script to run [IBM's Software TPM 2.0](https://sourceforge.net/projects/ibmswtpm2/) and the application in parallel inside a containerized instance
- `NVChip`: Starting NV memory state for [IBM's Software TPM 2.0](https://sourceforge.net/projects/ibmswtpm2/), which enables shared loading of the prover device's signing key during run-time across containerized instances

## Requirements

- [Docker](https://docker.com/)

## Building and running the container

To build the container, run the following command:

    docker build . -t prover:0.1.0

To start a container instance that binds a REST API on port 8085 run the following command:

    docker run --rm -it -p 8085:8085 prover:0.1.0 -api http://0.0.0.0:8085/api

Note that arguments past `prover:0.1.0` are passed as run-time arguments to the application (`main.cpp`) itself. The `-p` argument to docker is to publish the port assigned to the REST API (i.e., it should match that in the API URL/address). The complete list of parameters to the application are as follows:

        -api    local REST API address to listen on
                http://0.0.0.0:8085/api
        -v      verbose (log some errors and HTTP requests and responses to the console)

To build and deploy using docker compose run the following commands:

    docker-compose build
    docker-compose up

To build an image for the arm64 architecture:

    docker buildx build --platform linux/arm64 -t prover-0.1.0-arm64 .

## Timing output

To evaluate the real execution time, uncomment either of the following lines in `CMakeLists.txt`:

    #add_definitions(-DHIGHLEVELTIMINGS)
    #add_definitions(-DLOWLEVELTIMINGS)

Running the program with `HIGHLEVELTIMINGS` outputs the complete execution time for main functions, whereas `LOWLEVELTIMINGS` outputs the execution time of individual TPM2 function calls. Thus, turning on both metrics will affect the accuracy of the timings since the processing time for `LOWLEVELTIMINGS` will count towards `HIGHLEVELTIMINGS`.

## Limitations

The current containerized version has not been tested with hardware-based TPMs.

## Disclaimer

All implementations are only research prototypes.

## License
