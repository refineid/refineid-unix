# FreeBSD Automatic Network Failover (Ethernet and Wi-Fi)

Status: Active

Date: 2026-10-24

This document describes how to configure automatic network link failover
between wired Ethernet and wireless (Wi-Fi) interfaces on FreeBSD.

When Ethernet is plugged in, 100% of network traffic routes over the wired
connection. When unplugged, traffic transitions instantly to Wi-Fi at the
kernel level without losing active TCP sessions or changing the host's IP
address.

---

## 1. Architectural Overview

FreeBSD provides link aggregation and failover via **`lagg(4)`**:

* **Virtual Interface (`lagg0`)**: Binds the wired interface and wireless
  interface into a single logical network device.
* **Failover Protocol (`laggproto failover`)**: The first configured member
  is the **master**. When the master port has an active carrier link, traffic
  flows exclusively through it. When link carrier is lost, `lagg` fails over
  to the backup port instantly.
* **MAC Address Synchronization**: In failover mode, all member ports must
  present the same MAC address so switches, routers, and ARP caches see a single
  consistent identity. Because many Wi-Fi drivers do not support MAC spoofing,
  the wired interface clones the permanent hardware MAC of the Wi-Fi card.
* **Hot-Pluggable USB Ethernet**: If the wired interface is a USB adapter
  (e.g. `ue0`), it attaches asynchronously at boot and can be detached/attached
  dynamically. A `devd(8)` rule ensures it is promoted to master upon link
  establishment.

---

## 2. Kernel Module (`/boot/loader.conf`)

Ensure the `if_lagg` kernel module loads at boot:

```sh
sysrc -f /boot/loader.conf if_lagg_load="YES"
```

---

## 3. Network Configuration (`/etc/rc.conf`)

Identify your interface names with `ifconfig`:
* **Wired Ethernet interface**: e.g. `em0`, `igb0`, or `ue0`.
* **Wi-Fi parent device**: e.g. `iwlwifi0`, `iwm0`, or `rtw880`.

Obtain the permanent MAC address of the Wi-Fi card:
```sh
ifconfig <wifi_parent_device> | grep ether
```
*(Represented below as `02:00:00:00:00:01` or your device's actual MAC).*

Add the following block to `/etc/rc.conf`:

```sh
# 1. Match the wired interface MAC address to the wireless MAC
ifconfig_<wired_if>="ether 02:00:00:00:00:01 up"

# 2. Configure the wireless interface without standalone DHCP
wlans_<wifi_parent_device>="wlan0"
ifconfig_wlan0="WPA"
create_args_wlan0="country <COUNTRY_CODE> regdomain <REGDOMAIN>"

# 3. Create the failover lagg interface (wired is master, wlan0 is failover)
cloned_interfaces="lagg0"
ifconfig_lagg0="up laggproto failover laggport <wired_if> laggport wlan0 DHCP"
ifconfig_lagg0_ipv6="inet6 accept_rtadv"
```

---

## 4. Wi-Fi Credentials (`/etc/wpa_supplicant.conf`)

Configure network credentials in `/etc/wpa_supplicant.conf`:

```text
ctrl_interface=/var/run/wpa_supplicant
eapol_version=2
ap_scan=1
fast_reauth=1

network={
    ssid="<YOUR_SSID>"
    scan_ssid=0
    psk="<YOUR_PASSPHRASE>"
    priority=5
}

network={
    priority=0
    key_mgmt=NONE
}
```

---

## 5. Dynamic Device Handling (`/usr/local/etc/devd/lagg_ue.conf`)

For laptops using USB Ethernet adapters (which may attach after initial boot
scripts or be re-plugged while running), create
`/usr/local/etc/devd/lagg_ue.conf`:

```text
# When the wired link carrier comes UP, ensure it is in lagg0 as MASTER
notify 100 {
    match "system"    "IFNET";
    match "subsystem" "<wired_if>";
    match "type"      "LINK_UP";
    action "ifconfig <wired_if> ether 02:00:00:00:00:01 up; ifconfig lagg0 laggport <wired_if> 2>/dev/null; ifconfig lagg0 -laggport wlan0 2>/dev/null; ifconfig lagg0 laggport wlan0 2>/dev/null";
};

# When USB Ethernet interface attaches
attach 100 {
    device-name "<wired_if>";
    action "ifconfig <wired_if> ether 02:00:00:00:00:01 up; ifconfig lagg0 laggport <wired_if> 2>/dev/null; ifconfig lagg0 -laggport wlan0 2>/dev/null; ifconfig lagg0 laggport wlan0 2>/dev/null";
};

# When USB Ethernet device detaches
detach 100 {
    device-name "<driver_prefix>[0-9]+";
    action "ifconfig lagg0 -laggport <wired_if> 2>/dev/null";
};
```

Restart `devd`:
```sh
service devd restart
```

---

## 6. Hostname Resolution via mDNS (Avahi)

To eliminate the need to track dynamic IP leases on development workstations,
enable mDNS:

```sh
sysrc dbus_enable="YES"
sysrc avahi_daemon_enable="YES"
service dbus start
service avahi-daemon start
```

On any local machine (macOS, Linux, etc.), the FreeBSD box is accessible via:
```sh
ssh user@<hostname>.local
```

In `~/.ssh/config` on client machines:
```ssh
host <shortname>
    hostname <hostname>.local
    user <username>
```

---

## 7. Verification

Verify the active port:
```sh
ifconfig lagg0
```

Expected output when wired is connected:
```text
laggproto failover lagghash l2,l3,l4
laggport: <wired_if> flags=5<MASTER,ACTIVE>
laggport: wlan0 flags=0<>
status: active
```

Expected output when wired is disconnected:
```text
laggproto failover lagghash l2,l3,l4
laggport: wlan0 flags=5<MASTER,ACTIVE>
status: active
```

Verify traffic counters during testing:
```sh
netstat -I <wired_if>
netstat -I wlan0
```
When plugged in, output packet counters increment exclusively on `<wired_if>`.
When unplugged, counters transition to `wlan0` without connection disruption.
