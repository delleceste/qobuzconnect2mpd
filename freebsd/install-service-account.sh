#!/bin/sh

set -eu

user="$1"
homedir="$2"
group="$user"

if [ "$(uname -s)" != "FreeBSD" ]; then
	exit 0
fi

if [ -n "${DESTDIR:-}" ]; then
	echo "Skipping ${user} account creation during DESTDIR install."
	exit 0
fi

if ! /usr/sbin/pw groupshow "$group" >/dev/null 2>&1; then
	/usr/sbin/pw groupadd "$group"
fi

if ! /usr/sbin/pw usershow "$user" >/dev/null 2>&1; then
	/usr/sbin/pw useradd "$user" \
		-c "Qobuz Connect to MPD daemon" \
		-d "$homedir" \
		-g "$group" \
		-s /usr/sbin/nologin
fi

/usr/bin/install -d -o "$user" -g "$group" -m 0700 "$homedir"
/usr/bin/install -d -o "$user" -g "$group" -m 0755 "$homedir/.cache/qobuzconnect2mpd"
