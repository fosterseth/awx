#!/bin/bash
set +x

# Wait for the databases to come up
while ! nc -z postgres 5432; do
    sleep 0.1
done
while ! nc -z -U /var/run/redis/redis.sock; do
    sleep 0.1
done

# # In case AWX in the container wants to connect to itself, use "docker exec" to attach to the container otherwise
# # TODO: FIX
# #/etc/init.d/ssh start

# Move to the source directory so we can bootstrap
if [ -f "/awx_devel/manage.py" ]; then
    cd /awx_devel
else
    echo "Failed to find awx source tree, map your development tree volume"
fi

make awx-link

# AWX bootstrapping
make version_file
make migrate
make init

mkdir -p /awx_devel/awx/public/static
mkdir -p /awx_devel/awx/ui/static
mkdir -p /awx_devel/awx/ui_next/build/static
