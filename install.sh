#!/bin/sh
set -eu

fail() { printf '%s\n' "Hata: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "Kurulumu sudo sh ./install.sh ile çalıştırın."
[ "$(uname -s)" = Linux ] || fail "Bu servis Linux/systemd içindir."
for command_name in python3 journalctl nft systemctl install stat; do
    command -v "$command_name" >/dev/null 2>&1 || fail "$command_name bulunamadı. Önce: sudo apt-get update && sudo apt-get install python3 nftables systemd openssh-server"
done
[ -d /run/systemd/system ] || fail "systemd çalışmıyor."
/usr/bin/python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' || fail "Python 3.10 veya yenisi gerekli."
if systemctl is-active --quiet ssh-guard.service; then
    fail "Güncellemeden önce sudo systemctl stop ssh-guard komutuyla servisi durdurun. Mevcut IP engelleri kalır."
fi

source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -f "$source_dir/config.conf" ] || fail "config.conf bulunamadı. Paketin tamamını aynı dizine açın."
[ -f "$source_dir/ssh_guard/__main__.py" ] || fail "ssh_guard paketi eksik."

# Never follow an existing symlink at a destination controlled by this installer.
for target_path in /opt/ssh-guard /opt/ssh-guard/ssh_guard /opt/ssh-guard/README.md /etc/ssh-guard /var/lib/ssh-guard /usr/local/bin/ssh-guard /etc/systemd/system/ssh-guard.service /etc/ssh-guard/config.conf /etc/ssh-guard/smtp.env; do
    [ ! -L "$target_path" ] || fail "Sembolik bağlantı hedefi reddedildi: $target_path"
    if [ -e "$target_path" ]; then
        [ "$(stat -c '%u' "$target_path")" -eq 0 ] || fail "Hedef root kullanıcısına ait olmalı: $target_path"
    fi
done

install -d -o root -g root -m 0755 /opt/ssh-guard /opt/ssh-guard/ssh_guard /usr/local/bin
install -d -o root -g root -m 0700 /etc/ssh-guard /var/lib/ssh-guard
for source_file in "$source_dir"/ssh_guard/*.py; do
    destination_file="/opt/ssh-guard/ssh_guard/$(basename -- "$source_file")"
    [ ! -L "$destination_file" ] || fail "Sembolik bağlantı hedefi reddedildi: $destination_file"
    install -o root -g root -m 0644 "$source_file" "$destination_file"
done
install -o root -g root -m 0644 "$source_dir/README.md" /opt/ssh-guard/README.md
install -o root -g root -m 0644 "$source_dir/deploy/ssh-guard.service" /etc/systemd/system/ssh-guard.service

if [ ! -e /etc/ssh-guard/config.conf ]; then
    install -o root -g root -m 0600 "$source_dir/config.conf" /etc/ssh-guard/config.conf
else
    printf '%s\n' 'Mevcut /etc/ssh-guard/config.conf korundu.'
fi
if [ ! -e /etc/ssh-guard/smtp.env ]; then
    install -o root -g root -m 0600 "$source_dir/deploy/smtp.env.example" /etc/ssh-guard/smtp.env
else
    printf '%s\n' 'Mevcut /etc/ssh-guard/smtp.env korundu.'
fi
chmod 0600 /etc/ssh-guard/config.conf /etc/ssh-guard/smtp.env

cat > /usr/local/bin/ssh-guard <<'LAUNCHER'
#!/bin/sh
export PYTHONDONTWRITEBYTECODE=1
cd /opt/ssh-guard || exit 1
exec /usr/bin/python3 -m ssh_guard "$@"
LAUNCHER
chown root:root /usr/local/bin/ssh-guard
chmod 0755 /usr/local/bin/ssh-guard
systemctl daemon-reload
printf '%s\n' \
    'Kurulum tamamlandı. Servis başlatılmadı veya etkinleştirilmedi.' \
    '1. /etc/ssh-guard/config.conf: allowlist içine kendi yönetim IP/CIDR adresinizi, SMTP ve alıcı bilgilerini girin.' \
    '2. /etc/ssh-guard/smtp.env: SMTP parolasını girin.' \
    '3. sudo ssh-guard validate' \
    '4. sudo systemctl enable --now ssh-guard' \
    '5. sudo journalctl -u ssh-guard -f' \
    'Ayrıntılar: /opt/ssh-guard/README.md'
