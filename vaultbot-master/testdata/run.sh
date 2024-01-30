#!/bin/bash
docker run --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:1234' -p 1234:1234 -v $(pwd)/testdata/setup.sh:/tmp/setup.sh -d --name vault vault:1.1.0
sleep 5
docker exec vault sh /tmp/setup.sh
