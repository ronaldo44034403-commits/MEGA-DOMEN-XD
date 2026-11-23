#!/usr/bin/env bash
# Установка поддержки домена .xd в Termux:  bash install.sh https://адрес-панели
set -e
REG="${1:-http://100.189.67.15:4403}"
DIR="$(cd "$(dirname "$0")" && pwd)"
PFX="${PREFIX:-/data/data/com.termux/files/usr}"

echo "[xd] ставлю python..."
pkg install -y python >/dev/null 2>&1 || pkg install -y python

mkdir -p "$HOME/.xd"
cp "$DIR/xd.py" "$HOME/.xd/xd.py"

cat > "$PFX/bin/xd" <<EOF
#!/usr/bin/env bash
exec python "$HOME/.xd/xd.py" "\$@"
EOF
chmod +x "$PFX/bin/xd"

if [ -n "$REG" ]; then
  python "$HOME/.xd/xd.py" config "$REG"
fi

echo
echo "✅ Готово. Команда: xd"
echo "   xd config https://адрес-панели   (если не указал при установке)"
echo "   xd start | stop | status | list"
