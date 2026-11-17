#!/usr/bin/env bash
# Instala o Autenticador para o usuário atual (Linux com GNOME/GTK4).
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
if ! python3 -c "import gi; gi.require_version('Gtk','4.0'); gi.require_version('Adw','1'); gi.require_version('Secret','1')" 2>/dev/null; then
  echo "Faltam as bibliotecas do sistema. Instale e rode de novo:"
  echo "  Fedora: sudo dnf install python3-gobject gtk4 libadwaita libsecret"
  echo "  Ubuntu/Debian: sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-secret-1"
  exit 1
fi
python3 -m venv --system-site-packages "$DIR/.venv"
"$DIR/.venv/bin/pip" install -q -r "$DIR/requirements.txt"
mkdir -p ~/.local/share/applications
cat > ~/.local/share/applications/io.github.arthur.Autenticador.desktop <<DESKTOP
[Desktop Entry]
Type=Application
Name=Autenticador
Comment=Códigos de verificação em 2 etapas (2FA)
Exec=$DIR/.venv/bin/python -I $DIR/autenticador.py
Icon=dialog-password
Terminal=false
Categories=Utility;Security;
Keywords=2fa;totp;otp;authenticator;autenticador;
StartupWMClass=io.github.arthur.Autenticador
DESKTOP
update-desktop-database ~/.local/share/applications 2>/dev/null || true
echo "Pronto! Procure 'Autenticador' no menu de aplicativos."
echo "Ou rode: $DIR/.venv/bin/python -I $DIR/autenticador.py"
