# ASTRID Attestation Service running as part of the orchestration framework

This archive contains the containerized version of the attestation process performed by the Orchestrator. The Orchestrator communicates with the remote VF prover's 
exposed REST API and through appropriate Kafka topics to perform the necessary message exchanges.

## Contents

- `include`: Header files
- `libs`: Dependencies
- `src`: Source files
- `CMakeLists.txt`: Project file
- `docker-compose.yml`: Docker compose file
- `DockerFile`: Build file for containerized execution environment
- `main.cpp`: Application that performs secure enrollment
- `orchestratorSigningKeyPrivate`: Private part of Orchestrator's signing key (endorsement key)
- `orchestratorSigningKeyPublic`: Public part of Orchestrator's signing key (endorsement key)
- `vmSigningKeyPublic`: Public part of remote device's signing key (endorsement key)
- `run.sh`: Script to run [IBM's Software TPM 2.0](https://sourceforge.net/projects/ibmswtpm2/) and the application in parallel inside a containerized instance
- `NVChip`: Starting NV memory state for [IBM's Software TPM 2.0](https://sourceforge.net/projects/ibmswtpm2/), which enables shared loading of the Orchestrator's signing key during run-time across containerized instances

## Requirements

- [Docker](https://docker.com/)

## Building and running the container

To build the container run the following command:

    docker build . -t orchestrator:0.1.0

To start a container instance that binds a REST API on port 8080 run the following command:

    docker run --rm -it -p 8080:8080 orchestrator:0.1.0 -api http://0.0.0.0:8080/api

Note that arguments past `orchestrator:0.1.0` are passed as run-time arguments to the application (`main.cpp`) itself. The `-p` argument to docker is to publish the port assigned to the REST API (i.e., it should match that in the API URL/address). The complete list of parameters to the application are as follows:

        -api    local REST API address to listen on
                http://0.0.0.0:8080/api
        -v      verbose (log some errors and HTTP requests and responses to the console)

To build and deploy using docker compose run the following commands:

    docker-compose build
    docker-compose up

To build an image for the arm64 architecture:

    docker buildx build --platform linux/arm64 -t orchestrator-0.1.0-arm64 .

## Performing Secure Enrollment of a remote prover

To perform secure enrollment of a prover, use some HTTP client to send a HTTP POST request to http://0.0.0.0:8080/api/enroll and specify the URL of the remote prover's REST API in the request body as a JSON object as follows:

    {
        "proverApi": "http://[IPv6 address of prover]:port/api"
    }

Successful enrollment is determined by the HTTP status code `200 OK` and a response body as follows:

    {
        "msg": "Enrolled"
    }

Unsuccessful enrollment is determined by the HTTP status code `500 Internal Error`, where the `msg` field in the JSON object of the response body gives the stage that failed. For example, if secure establishment of an Attestation Key (AK) was unsuccessful, the following message is returned:

    {
        "msg": "Failed to establish AK on prover"
    }

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
