#!/bin/sh
# Read-only hardening fact collector for Debian, Ubuntu and RHEL-family Linux.
#
# Gathers the configuration facts evaluated by hardening-auditor (SSH, PAM and password policy,
# sudo, services, firewall, auditd, sysctl, file permissions, updates, time sync, mounts, MAC)
# and writes them to a single JSON file. It only reads files and runs query commands
# (sshd -T, systemctl, auditctl -l, nft list...): it never changes the system and needs no
# network access. POSIX sh, no dependency beyond the base system.
#
# Run it as root (sudo): without root, sshd -T, /etc/shadow, sudoers, firewall rules and audit
# rules cannot be read and the related controls are reported as unknown.
#
# Usage: sudo sh collect.sh [-o OUTPUT.json]

set -u
umask 077
LC_ALL=C
export LC_ALL

COLLECTOR_VERSION="1.0.0"
OUTPUT=""

usage() {
    echo "Usage: $0 [-o OUTPUT.json]"
    echo "Read-only collector for hardening-auditor. Writes <hostname>-facts.json by default."
}

while [ $# -gt 0 ]; do
    case "$1" in
        -o | --output)
            [ $# -ge 2 ] || { usage >&2; exit 64; }
            OUTPUT="$2"
            shift 2
            ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; exit 64 ;;
    esac
done

HOSTNAME_VALUE=$(uname -n)
[ -n "$OUTPUT" ] || OUTPUT="./${HOSTNAME_VALUE}-facts.json"

FACTS=$(mktemp) || exit 1
WARNINGS=$(mktemp) || { rm -f "$FACTS"; exit 1; }
trap 'rm -f "$FACTS" "$WARNINGS"' EXIT
trap 'exit 130' INT TERM

# ----------------------------------------------------------------------------- JSON helpers
json_string() {
    # Prints its argument as a JSON string literal.
    printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | tr '\t' ' ' |
        sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' |
        awk 'BEGIN { printf "\"" } NR > 1 { printf "\\n" } { printf "%s", $0 } END { printf "\"" }'
}

fact_raw() { printf '%s: %s\n' "$(json_string "$1")" "$2" >>"$FACTS"; }
fact_str() { fact_raw "$1" "$(json_string "$2")"; }
fact_bool() { if [ "$2" = true ]; then fact_raw "$1" true; else fact_raw "$1" false; fi; }

fact_int() {
    # Emits a number, or nothing when the value is not an integer (the fact is then missing).
    case "$2" in
        '' | - | *[!0-9-]* | -*-* | ?*-*) return 0 ;;
        *) fact_raw "$1" "$2" ;;
    esac
}

fact_list() {
    # Emits stdin (one item per line, empty lines ignored) as a JSON array.
    items=""
    while IFS= read -r item || [ -n "$item" ]; do
        [ -n "$item" ] || continue
        if [ -z "$items" ]; then items=$(json_string "$item"); else items="$items, $(json_string "$item")"; fi
    done
    fact_raw "$1" "[$items]"
}

warn() { printf '%s\n' "$1" >>"$WARNINGS"; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" -eq 0 ]; }

unit_active() { has_cmd systemctl && systemctl is-active --quiet "$1" 2>/dev/null; }
unit_enabled() { has_cmd systemctl && systemctl is-enabled --quiet "$1" 2>/dev/null; }

last_value() {
    # last_value KEY FILE... : value of the last "KEY value" or "KEY = value" line, comments
    # ignored. Unexpanded glob patterns are skipped, so callers can pass dir/*.conf directly.
    key="$1"
    shift
    for file in "$@"; do [ -r "$file" ] && cat "$file"; done 2>/dev/null |
        sed -e 's/#.*//' |
        awk -v k="$key" '{
                line = $0; sub(/^[ 	]+/, "", line); if (line == "") next
                name = line; sub(/[ 	=].*$/, "", name)
                if (tolower(name) != tolower(k)) next
                v = substr(line, length(name) + 1); sub(/^[ 	]*=?[ 	]*/, "", v); sub(/[ 	]+$/, "", v)
                last = v
            }
            END { if (last != "") print last }'
}

if ! is_root; then
    warn "Not running as root: sshd -T, /etc/shadow, sudoers, firewall and audit rules are not collected."
fi

# ----------------------------------------------------------------------------- operating system
os_field() { sed -n "s/^$1=//p" /etc/os-release 2>/dev/null | tr -d '"' | head -n 1; }
OS_NAME=$(os_field PRETTY_NAME)
OS_VERSION=$(os_field VERSION_ID)
fact_str os.id "$(os_field ID)"
fact_str os.id_like "$(os_field ID_LIKE)"
fact_str os.kernel "$(uname -r)"

# ----------------------------------------------------------------------------- SSH server
SSHD=""
for candidate in sshd /usr/sbin/sshd /usr/local/sbin/sshd; do
    if has_cmd "$candidate"; then SSHD=$(command -v "$candidate"); break; fi
done
if [ -n "$SSHD" ]; then
    fact_bool ssh.installed true
    # sshd -T prints the effective configuration (includes, defaults and drop-ins resolved).
    if SSHD_CONFIG=$("$SSHD" -T 2>/dev/null) && [ -n "$SSHD_CONFIG" ]; then
        sshd_value() { printf '%s\n' "$SSHD_CONFIG" | awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }'; }
        for key in permitrootlogin passwordauthentication permitemptypasswords x11forwarding \
            hostbasedauthentication ignorerhosts loglevel usepam; do
            fact_str "ssh.$key" "$(sshd_value "$key")"
        done
        fact_int ssh.maxauthtries "$(sshd_value maxauthtries)"
        for key in ciphers macs kexalgorithms; do
            sshd_value "$key" | tr ',' '\n' | fact_list "ssh.$key"
        done
    else
        warn "sshd -T failed (needs root and a valid configuration): SSH settings not collected."
    fi
else
    fact_bool ssh.installed false
fi

# ----------------------------------------------------------------------------- passwords and PAM
fact_int login_defs.pass_max_days "$(last_value PASS_MAX_DAYS /etc/login.defs)"
fact_int login_defs.pass_min_days "$(last_value PASS_MIN_DAYS /etc/login.defs)"
fact_int login_defs.pass_warn_age "$(last_value PASS_WARN_AGE /etc/login.defs)"
ENCRYPT_METHOD=$(last_value ENCRYPT_METHOD /etc/login.defs)
[ -n "$ENCRYPT_METHOD" ] && fact_str login_defs.encrypt_method "$ENCRYPT_METHOD"

PAM_FILES=""
for file in /etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -r "$file" ] && PAM_FILES="$PAM_FILES $file"
done
pam_lines() {
    # Active lines of the PAM stacks; word splitting of PAM_FILES is intended.
    # shellcheck disable=SC2086
    [ -n "$PAM_FILES" ] && sed -e 's/#.*//' $PAM_FILES 2>/dev/null
}

if pam_lines | grep -Eq 'pam_pwquality\.so'; then
    MINLEN=$(pam_lines | sed -n 's/.*pam_pwquality\.so.*[[:space:]]minlen=\([0-9][0-9]*\).*/\1/p' | tail -n 1)
    if [ -z "$MINLEN" ]; then
        MINLEN=$(last_value minlen /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
    fi
    fact_int pam.pwquality.minlen "$MINLEN"
fi

if pam_lines | grep -Eq '^[[:space:]]*auth[[:space:]].*pam_(faillock|tally2)\.so'; then
    fact_bool pam.faillock.enabled true
    DENY=$(pam_lines | sed -n -E 's/.*pam_(faillock|tally2)\.so.*[[:space:]]deny=([0-9]+).*/\2/p' | tail -n 1)
    [ -n "$DENY" ] || DENY=$(last_value deny /etc/security/faillock.conf)
    fact_int pam.faillock.deny "$DENY"
else
    fact_bool pam.faillock.enabled false
fi

if [ -n "$PAM_FILES" ]; then
    if pam_lines | grep -Eq 'pam_unix\.so.*[[:space:]]nullok'; then fact_bool pam.nullok true; else fact_bool pam.nullok false; fi
else
    warn "No PAM stack found in /etc/pam.d (common-* or system-auth): PAM facts not collected."
fi

# ----------------------------------------------------------------------------- accounts
awk -F: '$3 == 0 { print $1 }' /etc/passwd | fact_list accounts.uid0
if [ -r /etc/shadow ]; then
    awk -F: '$2 == "" { print $1 }' /etc/shadow | fact_list accounts.empty_password
fi

# ----------------------------------------------------------------------------- sudo
if has_cmd sudo; then
    fact_bool sudo.installed true
    if [ -r /etc/sudoers ]; then
        SUDOERS=$(sed -e 's/#.*//' /etc/sudoers /etc/sudoers.d/* 2>/dev/null)
        # sudo 1.9.14 and later use a pseudo-terminal by default.
        SUDO_VERSION=$(sudo -V 2>/dev/null | sed -n 's/^Sudo version \([0-9.]*\).*/\1/p' | head -n 1)
        PTY_DEFAULT=$(printf '%s\n' "$SUDO_VERSION" | awk -F. '{ print ($1 > 1 || ($1 == 1 && ($2 > 9 || ($2 == 9 && $3 >= 14)))) ? "true" : "false" }')
        if printf '%s\n' "$SUDOERS" | grep -Eq 'Defaults.*!use_pty'; then
            fact_bool sudo.use_pty false
        elif printf '%s\n' "$SUDOERS" | grep -Eq 'Defaults.*use_pty'; then
            fact_bool sudo.use_pty true
        else
            fact_bool sudo.use_pty "$PTY_DEFAULT"
        fi
        if printf '%s\n' "$SUDOERS" | grep -Eq 'Defaults.*logfile[[:space:]]*='; then
            fact_bool sudo.logfile true
        else
            fact_bool sudo.logfile false
        fi
        fact_int sudo.nopasswd_entries "$(printf '%s\n' "$SUDOERS" | grep -c 'NOPASSWD')"
    fi
else
    fact_bool sudo.installed false
fi

# ----------------------------------------------------------------------------- services
if has_cmd systemctl; then
    {
        systemctl list-unit-files --type=service,socket --state=enabled --no-legend --no-pager 2>/dev/null | awk '{ print $1 }'
        systemctl list-units --type=service,socket --state=active --no-legend --no-pager --plain 2>/dev/null | awk '{ print $1 }'
    } | sed 's/\.service$//' | sort -u | fact_list services.enabled
else
    warn "systemctl not found: enabled services not collected."
fi

# ----------------------------------------------------------------------------- firewall
nft_filters_input() {
    nft list ruleset 2>/dev/null | awk '
        /^[[:space:]]*chain / { in_chain = 1; input = 0; rules = 0; drop = 0; next }
        in_chain && /hook input/ { input = 1; if ($0 ~ /policy drop/) drop = 1; next }
        in_chain && /^[[:space:]]*}/ { if (input && (drop || rules)) found = 1; in_chain = 0; next }
        in_chain && NF { rules++ }
        END { exit found ? 0 : 1 }'
}
FIREWALL=""
if has_cmd ufw && is_root && ufw status 2>/dev/null | grep -q '^Status: active'; then
    FIREWALL=ufw
elif unit_active firewalld; then
    FIREWALL=firewalld
elif has_cmd nft && is_root && nft_filters_input; then
    FIREWALL=nftables
elif has_cmd iptables && is_root && iptables -S INPUT 2>/dev/null | grep -Eq '^-P INPUT (DROP|REJECT)|^-A INPUT'; then
    FIREWALL=iptables
fi
if [ -n "$FIREWALL" ]; then
    fact_bool firewall.active true
    fact_str firewall.backend "$FIREWALL"
elif is_root; then
    fact_bool firewall.active false
fi

# ----------------------------------------------------------------------------- audit and logging
if unit_active auditd; then fact_bool auditd.active true; else fact_bool auditd.active false; fi
if unit_enabled auditd; then fact_bool auditd.enabled true; else fact_bool auditd.enabled false; fi
if grep -Eq '(^|[[:space:]])audit=1([[:space:]]|$)' /proc/cmdline 2>/dev/null; then
    fact_bool audit.boot_param true
else
    fact_bool audit.boot_param false
fi
if ! has_cmd auditctl; then
    fact_bool audit.rules_watch_identity false
    fact_bool audit.rules_watch_sudoers false
elif is_root; then
    AUDIT_RULES=$(auditctl -l 2>/dev/null)
    fact_int audit.rule_count "$(printf '%s\n' "$AUDIT_RULES" | grep -c '^-')"
    if printf '%s\n' "$AUDIT_RULES" | grep -q '/etc/passwd' && printf '%s\n' "$AUDIT_RULES" | grep -q '/etc/shadow'; then
        fact_bool audit.rules_watch_identity true
    else
        fact_bool audit.rules_watch_identity false
    fi
    if printf '%s\n' "$AUDIT_RULES" | grep -q '/etc/sudoers'; then
        fact_bool audit.rules_watch_sudoers true
    else
        fact_bool audit.rules_watch_sudoers false
    fi
fi

if unit_active rsyslog || unit_active syslog-ng; then fact_bool logging.rsyslog_active true; else fact_bool logging.rsyslog_active false; fi
STORAGE=$(last_value Storage /usr/lib/systemd/journald.conf.d/*.conf /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf)
case "$STORAGE" in
    persistent) fact_bool logging.journald_persistent true ;;
    '' | auto) if [ -d /var/log/journal ]; then fact_bool logging.journald_persistent true; else fact_bool logging.journald_persistent false; fi ;;
    *) fact_bool logging.journald_persistent false ;;
esac

# ----------------------------------------------------------------------------- kernel parameters
for key in kernel.randomize_va_space kernel.yama.ptrace_scope kernel.kptr_restrict kernel.dmesg_restrict \
    fs.suid_dumpable fs.protected_hardlinks fs.protected_symlinks \
    net.ipv4.ip_forward net.ipv6.conf.all.forwarding \
    net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects \
    net.ipv4.conf.all.secure_redirects net.ipv4.conf.all.send_redirects \
    net.ipv4.conf.all.accept_source_route net.ipv6.conf.all.accept_redirects \
    net.ipv6.conf.all.accept_source_route net.ipv4.conf.all.rp_filter \
    net.ipv4.tcp_syncookies net.ipv4.conf.all.log_martians net.ipv4.icmp_echo_ignore_broadcasts; do
    path="/proc/sys/$(printf '%s' "$key" | tr . /)"
    [ -r "$path" ] && fact_int "sysctl.$key" "$(head -n 1 "$path" | tr -d '[:space:]')"
done

# ----------------------------------------------------------------------------- file permissions
file_facts() {
    # file_facts NAME PATH : mode (4 octal digits), owner and group of PATH.
    [ -e "$2" ] || return 0
    set -- "$1" "$2" "$(stat -c '%a %U %G' "$2" 2>/dev/null)"
    [ -n "$3" ] || return 0
    fact_str "files.$1.mode" "$(printf '%s' "$3" | awk '{ printf "%04d", $1 }')"
    fact_str "files.$1.owner" "$(printf '%s' "$3" | awk '{ print $2 }')"
    fact_str "files.$1.group" "$(printf '%s' "$3" | awk '{ print $3 }')"
}
for file in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/ssh/sshd_config; do
    file_facts "$file" "$file"
done
for file in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
    if [ -e "$file" ]; then file_facts bootloader_cfg "$file"; break; fi
done

# ----------------------------------------------------------------------------- updates
if has_cmd apt-get; then
    # shellcheck disable=SC2016 # ${Status} is a dpkg-query format field, not a shell variable
    if dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'install ok installed'; then
        fact_bool updates.unattended_upgrades_installed true
    else
        fact_bool updates.unattended_upgrades_installed false
    fi
    fact_int updates.apt_unattended_upgrade "$(apt-config dump 2>/dev/null | sed -n 's/^APT::Periodic::Unattended-Upgrade "\([0-9]*\)";$/\1/p' | tail -n 1)"
fi
if has_cmd dnf; then
    APPLY=$(last_value apply_updates /etc/dnf/automatic.conf)
    if unit_enabled dnf-automatic-install.timer || { unit_enabled dnf-automatic.timer && [ "$APPLY" = yes ]; }; then
        fact_bool updates.dnf_automatic_timer_enabled true
    else
        fact_bool updates.dnf_automatic_timer_enabled false
    fi
fi

# ----------------------------------------------------------------------------- time synchronisation
SYNC=""
for unit in chrony chronyd systemd-timesyncd ntp ntpd ntpsec openntpd; do
    if unit_active "$unit"; then SYNC=$unit; break; fi
done
if [ -n "$SYNC" ]; then
    fact_bool time.sync_active true
    fact_str time.sync_service "$SYNC"
else
    fact_bool time.sync_active false
fi

# ----------------------------------------------------------------------------- mounts
TMP_OPTIONS=$(awk '$2 == "/tmp" { o = $4 } END { print o }' /proc/mounts)
if [ -n "$TMP_OPTIONS" ]; then
    fact_bool mounts.tmp.separate true
    printf '%s' "$TMP_OPTIONS" | tr ',' '\n' | fact_list mounts.tmp.options
else
    fact_bool mounts.tmp.separate false
fi
awk '$2 == "/dev/shm" { o = $4 } END { print o }' /proc/mounts | tr ',' '\n' | fact_list mounts.dev_shm.options

# ----------------------------------------------------------------------------- mandatory access control
if has_cmd getenforce; then
    fact_str mac.selinux "$(getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]')"
elif [ -r /sys/fs/selinux/enforce ]; then
    if [ "$(cat /sys/fs/selinux/enforce)" = 1 ]; then fact_str mac.selinux enforcing; else fact_str mac.selinux permissive; fi
else
    fact_str mac.selinux absent
fi
if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ]; then
    fact_bool mac.apparmor_enabled true
    if [ -r /sys/kernel/security/apparmor/profiles ]; then
        fact_int mac.apparmor_enforced_profiles "$(grep -c '(enforce)' /sys/kernel/security/apparmor/profiles)"
    fi
else
    fact_bool mac.apparmor_enabled false
fi

# ----------------------------------------------------------------------------- output
if is_root; then ELEVATED=true; else ELEVATED=false; fi
{
    printf '{\n  "schema_version": 1,\n'
    printf '  "collector": {"name": "hardening-auditor-linux", "version": %s},\n' "$(json_string "$COLLECTOR_VERSION")"
    printf '  "host": {\n'
    printf '    "hostname": %s,\n' "$(json_string "$HOSTNAME_VALUE")"
    printf '    "os_family": "linux",\n'
    printf '    "os_name": %s,\n' "$(json_string "${OS_NAME:-Linux}")"
    printf '    "os_version": %s,\n' "$(json_string "$OS_VERSION")"
    printf '    "collected_at": %s,\n' "$(json_string "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
    printf '    "elevated": %s\n  },\n' "$ELEVATED"
    printf '  "warnings": ['
    first=true
    while IFS= read -r line; do
        if [ "$first" = true ]; then first=false; else printf ','; fi
        printf '\n    %s' "$(json_string "$line")"
    done <"$WARNINGS"
    printf '\n  ],\n  "facts": {\n'
    sed -e 's/^/    /' -e '$!s/$/,/' "$FACTS"
    printf '  }\n}\n'
} >"$OUTPUT.tmp"
if ! mv "$OUTPUT.tmp" "$OUTPUT"; then
    echo "error: cannot write $OUTPUT" >&2
    exit 1
fi

echo "Collected $(wc -l <"$FACTS" | tr -d ' ') facts ($(wc -l <"$WARNINGS" | tr -d ' ') warning(s)) into $OUTPUT"
