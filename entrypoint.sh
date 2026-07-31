#!/bin/sh
# Root only long enough to make /data writable by the app user (volumes created
# by pre-1.3.0 root images are owned by root), then drop privileges for real.
set -e
if [ "$(id -u)" = "0" ]; then
    chown -R wmkb:wmkb /data
    if command -v setpriv >/dev/null 2>&1; then
        exec setpriv --reuid wmkb --regid wmkb --init-groups "$@"
    fi
    exec su -s /bin/sh wmkb -c 'exec "$@"' -- sh "$@"
fi
exec "$@"
