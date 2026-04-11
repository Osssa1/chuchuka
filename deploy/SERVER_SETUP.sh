#!/usr/bin/env bash
# Запуск на сервере Linux (Debian/Ubuntu) от root после клонирования репо.
# Перед запуском отредактируйте переменные в блоке ниже.

set -euo pipefail

DEPLOY_ROOT="${DEPLOY_ROOT:-/opt/xseo_ip_bot}"
RUN_USER="${RUN_USER:-www-data}"
RUN_GROUP="${RUN_GROUP:-www-data}"
VENV_PATH="${DEPLOY_ROOT}/venv"
ENV_FILE="${ENV_FILE:-/etc/xseo/environment}"

echo "==> DEPLOY_ROOT=$DEPLOY_ROOT"
echo "    Убедитесь, что репозиторий уже лежит в DEPLOY_ROOT (или задайте DEPLOY_ROOT)."

if [[ ! -f "$DEPLOY_ROOT/bot_admin_site/manage.py" ]]; then
  echo "Ошибка: нет $DEPLOY_ROOT/bot_admin_site/manage.py"
  exit 1
fi

if [[ ! -f "$DEPLOY_ROOT/POLICY_PERSONAL_DATA.md" ]]; then
  echo "Предупреждение: нет $DEPLOY_ROOT/POLICY_PERSONAL_DATA.md — страница согласия в Web App будет без текста политики."
fi

echo "==> venv + зависимости"
if [[ ! -d "$VENV_PATH" ]]; then
  python3 -m venv "$VENV_PATH"
fi
# shellcheck source=/dev/null
source "$VENV_PATH/bin/activate"
pip install -U pip wheel
pip install -r "$DEPLOY_ROOT/requirements.txt" -r "$DEPLOY_ROOT/deploy/requirements-gunicorn.txt"

echo "==> Django migrate"
cd "$DEPLOY_ROOT/bot_admin_site"
"$VENV_PATH/bin/python" manage.py migrate --noinput

echo "==> каталог для env и systemd"
mkdir -p /etc/xseo
mkdir -p "$(dirname "$ENV_FILE")"
if [[ ! -f "$ENV_FILE" ]]; then
  cp "$DEPLOY_ROOT/deploy/env.example" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "Создан $ENV_FILE — ОБЯЗАТЕЛЬНО отредактируйте (токен, URL, SECRET_KEY), затем:"
  echo "  systemctl daemon-reload && systemctl restart xseo-django-gunicorn xseo-bot"
  exit 0
fi

echo "==> systemd unit-ы (копирование .example → /etc/systemd/system/)"
for u in xseo-django-gunicorn xseo-bot; do
  src="$DEPLOY_ROOT/deploy/${u}.service.example"
  dst="/etc/systemd/system/${u}.service"
  if grep -q "/opt/xseo_ip_bot" "$src"; then
    sed "s|/opt/xseo_ip_bot|$DEPLOY_ROOT|g" "$src" >"$dst"
  else
    cp "$src" "$dst"
  fi
  sed -i "s|EnvironmentFile=/etc/xseo/environment|EnvironmentFile=$ENV_FILE|" "$dst" || true
done

chown -R "$RUN_USER:$RUN_GROUP" "$DEPLOY_ROOT" 2>/dev/null || true

echo "==> nginx: положите конфиг вручную из deploy/nginx-site.conf.example (certbot ssl), затем nginx -t && systemctl reload nginx"

systemctl daemon-reload
systemctl enable xseo-django-gunicorn xseo-bot
echo "Готово. Правьте $ENV_FILE и при необходимости unit-файлы (User/paths), затем:"
echo "  systemctl start xseo-django-gunicorn && systemctl start xseo-bot"
echo "  certbot --nginx -d YOUR_DOMAIN  # если ещё нет TLS"
