#!/bin/sh
set -e

if [ -n "${DATABASE_URL:-}" ] && [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
  echo "Running database migrations..."
  npx prisma migrate deploy --schema=./node_modules/@kapea/database/prisma/schema.prisma
fi

exec "$@"
