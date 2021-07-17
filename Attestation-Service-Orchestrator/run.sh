#!/bin/bash

cd /opt/ibmtpm/src
./tpm_server &

sleep 5

cd /app
./orchestrator "$@"
