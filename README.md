# Autenticador

App de 2FA (TOTP) para o desktop Linux, no estilo Google Authenticator, com um gerador de dados de teste para devs. Feito em Python com GTK 4 + libadwaita.

## Códigos 2FA

- Adiciona contas colando um print do QR code (Ctrl+V), abrindo uma imagem, digitando a chave secreta ou um link `otpauth://`.
- Importa a exportação do Google Authenticator (QR `otpauth-migration://`).
- Os segredos ficam num cofre local criptografado (scrypt + AES-256-GCM) com senha mestra.
- Opcional: desbloqueio por digital (fprintd + chaveiro do GNOME).
- Clique na conta para copiar o código; arraste ou use Alt+↑/↓ para reordenar; fixe favoritas no topo; organize em pastas.
- Exporta uma conta para outro app (Microsoft ou Google Authenticator) por QR code: menu ⋮ → Exportar para outro app. Mostra o código atual para conferir antes de remover daqui.
- Trocar senha mestra e exportar/importar backup criptografado pelo menu.

## Bloqueio automático

- Bloqueia junto com a tela do computador e antes de suspender.
- Bloqueia após N minutos com a janela sem foco (padrão 10; 0 desliga).
- Configurável em Preferências → Bloqueio automático.

## Gerador (aba Gerador, não precisa desbloquear)

- **CPF** e **CNPJ** válidos, inclusive o **CNPJ alfanumérico** (formato novo da Receita, a partir de julho/2026).
- **CEP** real com endereço (consulta o ViaCEP; precisa de internet) ou só com formato e faixa válidos do estado.
- Com ou sem pontuação, geração em lote (um por linha) e opção de gerar outro ao copiar.
- **Validar**: cole um CPF, CNPJ ou CEP e veja se é válido (e quais seriam os dígitos verificadores corretos).

## Requisitos

- Linux com GTK 4.12+ e libadwaita 1.6+ (GNOME 47 ou mais novo).
- Python 3.11+.
- Bibliotecas do sistema:
  - Fedora: `sudo dnf install python3-gobject gtk4 libadwaita libsecret`
  - Ubuntu/Debian: `sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-secret-1`

## Instalação

```bash
git clone https://github.com/Arthurdnl/autenticador.git
cd autenticador
./instalar.sh
```

O script cria um `.venv`, instala as dependências Python e adiciona o app ao menu de aplicativos.

Para rodar sem instalar o atalho:

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -I autenticador.py
```

## Onde ficam os dados

O cofre fica em `~/.local/share/autenticador/vault.json` (criptografado). Use o menu → Backup → Exportar backup para guardar uma cópia. A senha mestra não pode ser recuperada.

## Atalhos

| Atalho | Ação |
|---|---|
| Ctrl+1 / Ctrl+2 | Aba Códigos / Gerador |
| Ctrl+V | Colar print do QR code |
| Ctrl+N | Adicionar conta |
| Ctrl+L | Bloquear |
| Ctrl+R | Gerar tudo de novo (aba Gerador) |
| Esc | Voltar da pasta |
| Alt+↑ / Alt+↓ | Reordenar conta |

## Licença

MIT — veja [LICENSE](LICENSE).
