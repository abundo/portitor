#!/bin/sh
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Password recovery, run by portitor-recovery.service from the boot menu entry
# "Portitor password recovery": the system is up without the firewall, its GUI
# or any network service, and this is on the console. Whoever can choose the
# entry can edit the kernel line too, so it gives no one more access; it makes the
# recovery easy.
set -u
CONFIG_YAML=/etc/portitor/config.yaml
USER_NAME=portitor

echo
echo "Portitor password recovery (no services are running)"
while true; do
	echo
	echo "  1) Set the password of the console user $USER_NAME (login and sudo)"
	echo "  2) Reset a GUI user's password, or create a GUI admin"
	echo "  3) Reboot"
	printf "Choice: "
	read -r choice || choice=3
	case "$choice" in
	1)
		passwd "$USER_NAME"
		;;
	2)
		if [ ! -f "$CONFIG_YAML" ]; then
			echo "portitor-config is not installed on this system ($CONFIG_YAML is missing)."
			continue
		fi
		printf "GUI user name: "
		read -r name || continue
		[ -n "$name" ] || continue
		runuser -u "$USER_NAME" -- portitor-config -f "$CONFIG_YAML" createadmin "$name"
		;;
	3)
		break
		;;
	esac
done
systemctl --no-block reboot
