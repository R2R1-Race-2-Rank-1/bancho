#!/bin/sh

sed -i 's/MYSQL_ROOT_PASSWORD/'"$DB_PASS"'/g' config.ini
sed -i 's/CIKEYVALUE/'"$APP_CI_KEY"'/g' config.ini
exec "$@"