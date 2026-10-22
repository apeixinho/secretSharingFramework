#!/usr/bin/env bash
set -euo pipefail

# Runs once on first Mongo data-dir init (docker-entrypoint-initdb.d).
mongosh --quiet <<EOF
db = db.getSiblingDB('${MONGO_USER_DB}')
db.createUser({
  user: '${MONGO_USER}',
  pwd: '${MONGO_PASSWORD}',
  roles: [ { role: 'dbOwner', db: '${MONGO_USER_DB}' } ]
})
EOF
