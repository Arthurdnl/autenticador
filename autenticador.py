#!/usr/bin/env python3
"""Autenticador — app de 2FA (TOTP) local para o desktop.

Adicione contas colando um print do QR code (Ctrl+V), abrindo uma imagem,
ou digitando a chave secreta / link otpauth://. Os segredos ficam num cofre
local criptografado (scrypt + AES-256-GCM) protegido por senha mestra.

A aba Gerador cria CPF, CNPJ (inclusive alfanumérico) e CEP válidos para testes.
"""
import base64
import hashlib
import hmac
import json
import math
import os
import random
import re
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Secret", "1")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango, Secret  # noqa: E402

import cv2  # noqa: E402
import numpy as np  # noqa: E402
from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # noqa: E402

APP_ID = "io.github.Arthurdnl.Autenticador"
LEGACY_APP_ID = "io.github.arthur.Autenticador"  # até 17/11/2026
DATA_DIR = Path(GLib.get_user_data_dir()) / "autenticador"
VAULT_PATH = DATA_DIR / "vault.json"
SETTINGS_PATH = DATA_DIR / "settings.json"

DRAG_PREFIX = "autenticador-account:"

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


# ---------------------------------------------------------------- TOTP

class ParseError(Exception):
    pass


def normalize_secret(secret):
    return "".join(secret.split()).replace("-", "").upper().rstrip("=")


def b32decode(secret):
    s = normalize_secret(secret)
    return base64.b32decode(s + "=" * (-len(s) % 8))


def totp(acc, now=None):
    now = time.time() if now is None else now
    counter = int(now // acc["period"])
    mac = hmac.new(b32decode(acc["secret"]), struct.pack(">Q", counter),
                   ALGORITHMS[acc["algorithm"]]).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** acc["digits"]).zfill(acc["digits"])


def make_account(secret, issuer="", name="", algorithm="SHA1", digits=6, period=30):
    secret = normalize_secret(secret)
    try:
        if not secret or not b32decode(secret):
            raise ValueError
    except ValueError:
        raise ParseError("Chave secreta inválida (esperado texto Base32, ex.: JBSWY3DPEHPK3PXP).")
    algorithm = str(algorithm).upper()
    if algorithm not in ALGORITHMS:
        raise ParseError(f"Algoritmo não suportado: {algorithm}")
    try:
        digits, period = int(digits), int(period)
    except ValueError:
        raise ParseError("Dígitos/período inválidos.")
    if digits not in (6, 7, 8) or not 1 <= period <= 300:
        raise ParseError("Dígitos/período inválidos.")
    return {"id": uuid.uuid4().hex, "issuer": issuer.strip(), "name": name.strip(),
            "secret": secret, "algorithm": algorithm, "digits": digits, "period": period}


def parse_otpauth(uri):
    u = urllib.parse.urlparse(uri)
    if u.netloc.lower() != "totp":
        raise ParseError(f"Só códigos por tempo (TOTP) são suportados; este é '{u.netloc}'.")
    q = dict(urllib.parse.parse_qsl(u.query))
    if "secret" not in q:
        raise ParseError("O link otpauth:// não tem a chave secreta.")
    label = urllib.parse.unquote(u.path.lstrip("/"))
    issuer = q.get("issuer", "")
    if ":" in label:
        label_issuer, name = label.split(":", 1)
        issuer = issuer or label_issuer
    else:
        name = label
    return make_account(q["secret"], issuer, name, q.get("algorithm", "SHA1"),
                        q.get("digits", 6), q.get("period", 30))


def build_otpauth(acc):
    """Link otpauth://totp/... da conta (inverso de parse_otpauth)."""
    issuer, name = acc["issuer"], acc["name"]
    label = f"{issuer}:{name}" if issuer and name else (issuer or name or "Conta")
    params = {"secret": acc["secret"]}
    # só manda o que foge do padrão (SHA1, 6 dígitos, 30 s): QR menor e mais compatível
    if acc["algorithm"] != "SHA1":
        params["algorithm"] = acc["algorithm"]
    if acc["digits"] != 6:
        params["digits"] = acc["digits"]
    if acc["period"] != 30:
        params["period"] = acc["period"]
    if issuer:
        params["issuer"] = issuer
    return ("otpauth://totp/" + urllib.parse.quote(label, safe=":@")
            + "?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote))


def qr_png(text, scale=10):
    """PNG (bytes) do QR code de text, já com a margem branca."""
    img = cv2.QRCodeEncoder.create().encode(text)
    img = cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
    return cv2.imencode(".png", img)[1].tobytes()


def _varint(buf, i):
    result = shift = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return result, i


def _protobuf_fields(buf):
    i = 0
    while i < len(buf):
        key, i = _varint(buf, i)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, i = _varint(buf, i)
        elif wire == 2:
            length, i = _varint(buf, i)
            value, i = buf[i:i + length], i + length
        elif wire == 1:
            value, i = buf[i:i + 8], i + 8
        elif wire == 5:
            value, i = buf[i:i + 4], i + 4
        else:
            raise ParseError("Dados de exportação inválidos.")
        yield field, value


def parse_migration(uri):
    """Exportação do Google Authenticator (otpauth-migration://offline?data=...)."""
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(uri).query))
    try:
        data = q["data"].replace(" ", "+")
        payload = base64.b64decode(data + "=" * (-len(data) % 4))
        accounts = []
        for field, raw in _protobuf_fields(payload):
            if field != 1:
                continue
            p = dict(_protobuf_fields(raw))
            if p.get(6, 2) == 1:  # HOTP
                continue
            secret = base64.b32encode(p[1]).decode()
            algorithm = {2: "SHA256", 3: "SHA512"}.get(p.get(4), "SHA1")
            digits = 8 if p.get(5) == 2 else 6
            name = p.get(2, b"").decode()
            issuer = p.get(3, b"").decode()
            if ":" in name and not issuer:
                issuer, name = name.split(":", 1)
            accounts.append(make_account(secret, issuer, name, algorithm, digits, 30))
    except (KeyError, IndexError, ValueError, UnicodeDecodeError):
        raise ParseError("Não consegui ler a exportação do Google Authenticator.")
    if not accounts:
        raise ParseError("A exportação não contém contas TOTP.")
    return accounts


def parse_payload(text):
    """Retorna lista de contas para um link otpauth, ou None se não for link."""
    text = text.strip()
    low = text.lower()
    if low.startswith("otpauth-migration://"):
        return parse_migration(text)
    if low.startswith("otpauth://"):
        return [parse_otpauth(text)]
    return None


def decode_qr(img):
    """Decodifica QR codes de uma imagem (ndarray BGR/BGRA/gray). Retorna lista de textos."""
    if img is None:
        return []
    if img.ndim == 3 and img.shape[2] == 4:  # compõe transparência sobre branco
        alpha = img[:, :, 3:4].astype(np.float32) / 255.0
        img = (img[:, :, :3] * alpha + 255 * (1 - alpha)).astype(np.uint8)
    gray = img if img.ndim == 2 else cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    candidates = [gray]
    h, w = gray.shape[:2]
    if max(h, w) < 1200:
        candidates.append(cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_NEAREST))
    if max(h, w) > 2500:
        candidates.append(cv2.resize(gray, None, fx=0.5, fy=0.5, interpolation=cv2.INTER_AREA))
    candidates.append(cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1])
    candidates.append(255 - gray)  # QR claro em fundo escuro
    # borda branca ajuda quando o print está cortado rente ao QR
    candidates.append(cv2.copyMakeBorder(gray, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255))

    detector = cv2.QRCodeDetector()
    for c in candidates:
        try:
            ok, texts, _, _ = detector.detectAndDecodeMulti(c)
            found = [t for t in texts if t] if ok else []
            if found:
                return found
            text, _, _ = detector.detectAndDecode(c)
            if text:
                return [text]
        except cv2.error:
            continue
    return []


# ---------------------------------------------------------------- cofre

def _b64e(b):
    return base64.b64encode(b).decode()


def _b64d(s):
    return base64.b64decode(s)


def _atomic_write(path, text):
    """Grava em arquivo temporário e troca, para não deixar arquivo pela metade."""
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def derive_key(password, data):
    """Chave do cofre/backup `data` (dict do JSON gravado) para a senha."""
    return Scrypt(salt=_b64d(data["salt"]), length=32, n=data["kdf"]["n"], r=data["kdf"]["r"],
                  p=data["kdf"]["p"]).derive(password.encode())


def decrypt_vault(data, key):
    """Conteúdo do cofre/backup. Lança InvalidTag se a chave não servir."""
    return json.loads(AESGCM(key).decrypt(_b64d(data["nonce"]), _b64d(data["ciphertext"]), None))


class Vault:
    KDF = {"n": 2 ** 16, "r": 8, "p": 1}

    def __init__(self):
        self.key = None
        self.salt = None
        self.kdf = dict(self.KDF)
        self.accounts = []
        self.folders = []  # [{"id", "name"}], na ordem de criação

    @staticmethod
    def exists():
        return VAULT_PATH.exists()

    @property
    def unlocked(self):
        return self.key is not None

    @staticmethod
    def _derive(password, salt, kdf):
        return Scrypt(salt=salt, length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(password.encode())

    def create(self, password):
        self.accounts = []
        self.folders = []
        self.change_password(password)

    def change_password(self, password):
        """Novo salt e nova chave; regrava o cofre com ela."""
        self.salt = os.urandom(16)
        self.kdf = dict(self.KDF)
        self.key = self._derive(password, self.salt, self.kdf)
        self.save()

    def verify_password(self, password):
        return hmac.compare_digest(self._derive(password, self.salt, self.kdf), self.key)

    def unlock(self, password):
        """Lança InvalidTag se a senha estiver errada."""
        data = json.loads(VAULT_PATH.read_text())
        self._open(data, derive_key(password, data))

    def unlock_with_key(self, key):
        """Abre com a chave já derivada (guardada no chaveiro). Lança InvalidTag se não servir."""
        self._open(json.loads(VAULT_PATH.read_text()), key)

    def _open(self, data, key):
        content = decrypt_vault(data, key)
        self.key, self.salt, self.kdf = key, _b64d(data["salt"]), data["kdf"]
        self.accounts = content["accounts"]
        self.folders = content.get("folders", [])
        known = {f["id"] for f in self.folders}
        for a in self.accounts:  # conta apontando para pasta inexistente volta para "sem pasta"
            if a.get("folder") not in known:
                a.pop("folder", None)
        if not content.get("ordered"):
            # cofres antigos guardavam em ordem de inclusão e mostravam o mais novo
            # primeiro; agora a lista do cofre é a ordem de exibição
            self.accounts.reverse()

    def lock(self):
        self.key = None
        self.accounts = []
        self.folders = []

    def save(self):
        nonce = os.urandom(12)
        plain = json.dumps({"accounts": self.accounts, "folders": self.folders, "ordered": True}).encode()
        data = {"version": 1, "kdf": self.kdf, "salt": _b64e(self.salt), "nonce": _b64e(nonce),
                "ciphertext": _b64e(AESGCM(self.key).encrypt(nonce, plain, None))}
        _atomic_write(VAULT_PATH, json.dumps(data))

    def folder_name(self, fid):
        return next((f["name"] for f in self.folders if f["id"] == fid), None)

    def find_folder(self, name):
        name = name.strip().casefold()
        return next((f for f in self.folders if f["name"].casefold() == name), None)


# ---------------------------------------------------------------- digital

# A digital só diz "é você"; quem abre o cofre é a chave guardada no chaveiro do
# GNOME (destrancado no login). A senha mestra continua valendo sempre.
KEYRING_SCHEMA = Secret.Schema.new(APP_ID + ".VaultKey", Secret.SchemaFlags.NONE,
                                   {"vault": Secret.SchemaAttributeType.STRING})
_LEGACY_KEYRING_SCHEMA = Secret.Schema.new(LEGACY_APP_ID + ".VaultKey", Secret.SchemaFlags.NONE,
                                           {"vault": Secret.SchemaAttributeType.STRING})


def _keyring_attrs():
    return {"vault": str(VAULT_PATH)}


def keyring_migrate_legacy():
    """Move a chave guardada com o identificador antigo do app para o novo, para a digital
    continuar funcionando sem precisar reativar."""
    try:
        secret = Secret.password_lookup_sync(_LEGACY_KEYRING_SCHEMA, _keyring_attrs(), None)
        if not secret:
            return
        if not Secret.password_lookup_sync(KEYRING_SCHEMA, _keyring_attrs(), None):
            keyring_store_key(_b64d(secret))
        Secret.password_clear_sync(_LEGACY_KEYRING_SCHEMA, _keyring_attrs(), None)
    except GLib.Error:
        pass


def keyring_has_key():
    try:
        return bool(Secret.password_search_sync(KEYRING_SCHEMA, _keyring_attrs(),
                                                Secret.SearchFlags.NONE, None))
    except GLib.Error:
        return False


def keyring_store_key(key):
    Secret.password_store_sync(KEYRING_SCHEMA, _keyring_attrs(), Secret.COLLECTION_DEFAULT,
                               "Autenticador — chave do cofre (desbloqueio por digital)",
                               _b64e(key), None)


def keyring_load_key():
    secret = Secret.password_lookup_sync(KEYRING_SCHEMA, _keyring_attrs(), None)
    return _b64d(secret) if secret else None


def keyring_clear_key():
    try:
        Secret.password_clear_sync(KEYRING_SCHEMA, _keyring_attrs(), None)
    except GLib.Error:
        pass


class Fingerprint:
    """Verificação de digital pelo fprintd (D-Bus do sistema)."""
    BUS = "net.reactivated.Fprint"
    MAX_ATTEMPTS = 5
    RETRY_DELAY_MS = 1000  # dá tempo de tirar o dedo antes de ler de novo
    SAME_TOUCH_S = 1.5  # falha logo após reiniciar = mesmo dedo ainda encostado
    MESSAGES = {
        "verify-retry-scan": "Leitura falhou. Encoste o dedo de novo.",
        "verify-swipe-too-short": "Leitura muito rápida. Encoste o dedo de novo.",
        "verify-finger-not-centered": "Centralize o dedo no leitor.",
        "verify-remove-and-retry": "Tire o dedo e encoste de novo.",
    }

    def __init__(self):
        self.device = None
        self._signal_id = None
        self._on_result = None
        self.attempts = 0
        self._retry_source = None
        self._verify_started = 0.0

    @property
    def running(self):
        return self.device is not None

    @classmethod
    def _proxy(cls, path, iface):
        return Gio.DBusProxy.new_for_bus_sync(Gio.BusType.SYSTEM, Gio.DBusProxyFlags.NONE, None,
                                              cls.BUS, path, f"{cls.BUS}.{iface}", None)

    @classmethod
    def _default_device(cls):
        manager = cls._proxy("/net/reactivated/Fprint/Manager", "Manager")
        path = manager.call_sync("GetDefaultDevice", None, Gio.DBusCallFlags.NONE, 5000, None)[0]
        return cls._proxy(path, "Device")

    @classmethod
    def available(cls):
        """Há leitor e o usuário tem ao menos um dedo cadastrado."""
        try:
            fingers = cls._default_device().call_sync(
                "ListEnrolledFingers", GLib.Variant("(s)", ("",)), Gio.DBusCallFlags.NONE, 5000, None)[0]
            return bool(fingers)
        except GLib.Error:
            return False

    def start(self, on_result):
        """on_result(kind, message): kind é "match", "status" (dica/tente de novo) ou "error"."""
        self.stop()
        self._on_result = on_result
        self.attempts = 0
        try:
            device = self._default_device()
            device.call_sync("Claim", GLib.Variant("(s)", ("",)), Gio.DBusCallFlags.NONE, 5000, None)
        except GLib.Error as e:
            busy = "AlreadyInUse" in str(e)
            on_result("error", "O leitor está em uso por outro programa." if busy
                      else "Leitor de digital indisponível.")
            return
        self.device = device
        self._signal_id = device.connect("g-signal", self._on_signal)
        self._verify()

    def _verify(self):
        self._retry_source = None
        if self.device is None:
            return GLib.SOURCE_REMOVE
        self._verify_started = time.monotonic()
        try:
            self.device.call_sync("VerifyStart", GLib.Variant("(s)", ("any",)),
                                  Gio.DBusCallFlags.NONE, 5000, None)
        except GLib.Error:
            self._finish("error", "Não consegui iniciar a leitura da digital.")
        return GLib.SOURCE_REMOVE

    def _on_signal(self, _proxy, _sender, signal, params):
        if signal != "VerifyStatus" or self.device is None:
            return
        result, done = params.unpack()
        if result == "verify-match":
            self._finish("match", None)
        elif not done:
            self._on_result("status", self.MESSAGES.get(result, "Encoste o dedo de novo."))
        elif result == "verify-no-match":
            same_touch = self.attempts and time.monotonic() - self._verify_started < self.SAME_TOUCH_S
            if not same_touch:
                self.attempts += 1
            if self.attempts >= self.MAX_ATTEMPTS:
                self._finish("error", "Digital não reconhecida. Use a senha mestra.")
                return
            self._on_result("status", f"Digital não reconhecida ({self.attempts} de {self.MAX_ATTEMPTS}). "
                                      "Tire o dedo e encoste de novo.")
            self._call_quiet("VerifyStop")
            self._retry_source = GLib.timeout_add(self.RETRY_DELAY_MS, self._verify)
        else:
            self._finish("error", "Erro no leitor de digital.")

    def _finish(self, kind, message):
        on_result = self._on_result
        self.stop()
        if on_result:
            on_result(kind, message)

    def _call_quiet(self, method):
        try:
            self.device.call_sync(method, None, Gio.DBusCallFlags.NONE, 5000, None)
        except GLib.Error:
            pass

    def stop(self):
        if self._retry_source:
            GLib.source_remove(self._retry_source)
            self._retry_source = None
        if self.device is None:
            return
        self.device.disconnect(self._signal_id)
        self._call_quiet("VerifyStop")
        self._call_quiet("Release")
        self.device = None
        self._on_result = None


# ---------------------------------------------------------------- gerador (dados de teste)

_rng = random.SystemRandom()


def _only_digits(text):
    return re.sub(r"\D", "", text)


def _cpf_dv(digits):
    """Recebe os 9 dígitos (lista de int) e devolve os 11, com os verificadores."""
    digits = list(digits)
    for n in (9, 10):
        s = sum(d * w for d, w in zip(digits, range(n + 1, 1, -1)))
        digits.append(s * 10 % 11 % 10)
    return digits


def generate_cpf():
    while True:
        base = [_rng.randrange(10) for _ in range(9)]
        if len(set(base)) > 1:  # 111.111.111-11 e afins são inválidos
            return "".join(map(str, _cpf_dv(base)))


def format_cpf(d):
    return f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:]}"


_CNPJ_WEIGHTS = (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)
_CNPJ_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _cnpj_dv(base):
    """Recebe os 12 primeiros caracteres e devolve os 14. Vale para o CNPJ alfanumérico:
    cada caractere vale ord(c) - 48 (0–9 → 0–9, A → 17 … Z → 42)."""
    values = [ord(c) - 48 for c in base]
    for n in (12, 13):
        r = sum(v * w for v, w in zip(values, _CNPJ_WEIGHTS[13 - n:])) % 11
        values.append(0 if r < 2 else 11 - r)
    return "".join(base) + f"{values[12]}{values[13]}"


def generate_cnpj(alnum=False):
    while True:
        if alnum:  # raiz com ao menos uma letra; filial 0001
            root = [_rng.choice(_CNPJ_CHARS) for _ in range(8)]
            if any(c.isalpha() for c in root):
                break
        else:
            root = [str(_rng.randrange(10)) for _ in range(8)]
            if len(set(root)) > 1:
                break
    return _cnpj_dv(root + list("0001"))


def format_cnpj(d):
    return f"{d[:2]}.{d[2:5]}.{d[5:8]}/{d[8:12]}-{d[12:]}"


def format_cep(d):
    return f"{d[:5]}-{d[5:]}"


# faixas de CEP por UF (5 primeiros dígitos)
CEP_RANGES = {
    "AC": [(69900, 69999)], "AL": [(57000, 57999)], "AM": [(69000, 69299), (69400, 69899)],
    "AP": [(68900, 68999)], "BA": [(40000, 48999)], "CE": [(60000, 63999)],
    "DF": [(70000, 72799), (73000, 73699)], "ES": [(29000, 29999)],
    "GO": [(72800, 72999), (73700, 76799)], "MA": [(65000, 65999)], "MG": [(30000, 39999)],
    "MS": [(79000, 79999)], "MT": [(78000, 78899)], "PA": [(66000, 68899)], "PB": [(58000, 58999)],
    "PE": [(50000, 56999)], "PI": [(64000, 64999)], "PR": [(80000, 87999)], "RJ": [(20000, 28999)],
    "RN": [(59000, 59999)], "RO": [(78900, 78999)], "RR": [(69300, 69399)], "RS": [(90000, 99999)],
    "SC": [(88000, 89999)], "SE": [(49000, 49999)], "SP": [(1000, 19999)], "TO": [(77000, 77999)],
}
UF_CAPITALS = {
    "AC": "Rio Branco", "AL": "Maceió", "AM": "Manaus", "AP": "Macapá", "BA": "Salvador",
    "CE": "Fortaleza", "DF": "Brasília", "ES": "Vitória", "GO": "Goiânia", "MA": "São Luís",
    "MG": "Belo Horizonte", "MS": "Campo Grande", "MT": "Cuiabá", "PA": "Belém", "PB": "João Pessoa",
    "PE": "Recife", "PI": "Teresina", "PR": "Curitiba", "RJ": "Rio de Janeiro", "RN": "Natal",
    "RO": "Porto Velho", "RR": "Boa Vista", "RS": "Porto Alegre", "SC": "Florianópolis",
    "SE": "Aracaju", "SP": "São Paulo", "TO": "Palmas",
}
# palavras comuns em nomes de rua, para sortear endereços reais no ViaCEP
CEP_WORDS = ("Brasil", "Santos", "Silva", "Pedro", "José", "Maria", "João", "Paulo", "Santa",
             "Flores", "Barão", "Dom", "General", "Sete", "Amazonas", "Bahia", "Minas", "Paraná",
             "Nova", "Lima", "Souza", "Oliveira", "Castro", "Alves", "Costa", "Bento")
VIACEP_TIMEOUT = 6


def random_cep(uf):
    """CEP com formato e faixa válidos para a UF (não garante que exista)."""
    lo, hi = _rng.choice(CEP_RANGES[uf])
    return f"{_rng.randint(lo, hi):05d}{_rng.randrange(1000):03d}"


def _viacep(path):
    req = urllib.request.Request("https://viacep.com.br/ws/" + path + "/json/",
                                 headers={"User-Agent": "Autenticador"})
    with urllib.request.urlopen(req, timeout=VIACEP_TIMEOUT) as r:
        return json.loads(r.read())


def fetch_real_ceps(uf):
    """CEPs reais da capital da UF (consulta o ViaCEP). Lança OSError sem rede."""
    city = urllib.parse.quote(UF_CAPITALS[uf])
    for word in _rng.sample(CEP_WORDS, 4):
        try:
            data = _viacep(f"{uf}/{city}/{urllib.parse.quote(word)}")
        except urllib.error.HTTPError:
            continue
        if isinstance(data, list) and data:
            return data
    return []


def lookup_cep(cep):
    """Endereço do CEP no ViaCEP, ou None se não existir. Lança OSError sem rede."""
    data = _viacep(cep)
    return None if not isinstance(data, dict) or data.get("erro") else data


def format_address(e):
    """Linha curta para exibir: logradouro — bairro — cidade/UF."""
    city = f"{e.get('localidade', '')}/{e.get('uf', '')}"
    return " — ".join(p for p in (e.get("logradouro"), e.get("bairro"), city) if p)


def full_address(e):
    """Endereço completo para colar em formulário."""
    city = f"{e.get('localidade', '')} - {e.get('uf', '')}"
    parts = (e.get("logradouro"), e.get("complemento"), e.get("bairro"), city, "CEP " + e.get("cep", ""))
    return ", ".join(p for p in parts if p)


def check_document(text):
    """Identifica e valida CPF, CNPJ (numérico ou alfanumérico) ou CEP.
    Retorna (tipo, ok, mensagem) ou None se vazio."""
    raw = re.sub(r"[^0-9A-Za-z]", "", text).upper()
    if not raw:
        return None
    if len(raw) == 11 and raw.isdigit():
        if len(set(raw)) == 1:
            return "CPF", False, "Todos os dígitos iguais: CPF inválido."
        expected = "".join(map(str, _cpf_dv(int(c) for c in raw[:9])))[9:]
        if raw[9:] == expected:
            return "CPF", True, f"{format_cpf(raw)} é um CPF válido."
        return "CPF", False, f"CPF inválido: os dígitos verificadores seriam {expected}."
    if len(raw) == 14:
        kind = "CNPJ" if raw.isdigit() else "CNPJ alfanumérico"
        if not raw[12:].isdigit():
            return kind, False, "Os 2 últimos caracteres (verificadores) precisam ser números."
        if raw.isdigit() and len(set(raw)) == 1:
            return kind, False, "Todos os dígitos iguais: CNPJ inválido."
        expected = _cnpj_dv(raw[:12])[12:]
        if raw[12:] == expected:
            return kind, True, f"{format_cnpj(raw)} é um {kind} válido."
        return kind, False, f"{kind} inválido: os dígitos verificadores seriam {expected}."
    if len(raw) == 8 and raw.isdigit():
        uf = next((u for u, ranges in CEP_RANGES.items()
                   if any(lo <= int(raw[:5]) <= hi for lo, hi in ranges)), None)
        if uf is None:
            return "CEP", False, f"{format_cep(raw)} não está em nenhuma faixa de CEP do Brasil."
        return "CEP", True, f"{format_cep(raw)}: formato válido, faixa de {uf}."
    return None, False, f"{len(raw)} caracteres: não é CPF (11), CNPJ (14) nem CEP (8)."


# ---------------------------------------------------------------- preferências

class Settings:
    """Preferências (não são segredo; ficam fora do cofre)."""
    DEFAULTS = {
        "home_shows_folder_codes": False,  # tela inicial lista também as contas das pastas
        "folders_per_row": 2,  # cartões de pasta lado a lado (1–4)
        "code_columns": 1,  # colunas de contas (1–2)
        "lock_on_screen_lock": True,  # bloqueia junto com a tela do computador / suspensão
        "auto_lock_minutes": 10,  # bloqueia após N min com a janela sem foco (0 = nunca)
        "gen_formatted": True,  # gerador: com pontuação
        "gen_cnpj_alnum": False,  # gerador: CNPJ alfanumérico
        "gen_cep_uf": "",  # gerador: UF do CEP ("" = qualquer)
        "gen_cep_real": True,  # gerador: CEP real consultando o ViaCEP
        "gen_new_after_copy": False,  # gerador: gera outro ao copiar
    }
    LIMITS = {"folders_per_row": (1, 4), "code_columns": (1, 2), "auto_lock_minutes": (0, 120)}

    def __init__(self):
        self.data = dict(self.DEFAULTS)
        try:
            saved = json.loads(SETTINGS_PATH.read_text())
            saved = saved if isinstance(saved, dict) else {}
        except (OSError, ValueError):
            saved = {}
        for key, default in self.DEFAULTS.items():
            value = saved.get(key, default)
            if isinstance(default, bool):
                ok = isinstance(value, bool)
            elif isinstance(default, int):  # bool também é int em Python: não aceita
                ok = isinstance(value, (int, float)) and not isinstance(value, bool)
            else:
                ok = isinstance(value, type(default))
            if not ok:
                value = default
            elif key in self.LIMITS:
                lo, hi = self.LIMITS[key]
                value = min(max(int(value), lo), hi)
            self.data[key] = value
        if self.data["gen_cep_uf"] not in CEP_RANGES:
            self.data["gen_cep_uf"] = ""

    def __getitem__(self, key):
        return self.data[key]

    def set(self, key, value):
        self.data[key] = value
        try:
            _atomic_write(SETTINGS_PATH, json.dumps(self.data))
        except OSError:
            pass


# ---------------------------------------------------------------- UI

CSS = """
.otp-code { font-family: monospace; font-size: 1.55em; font-weight: bold; }
.otp-code.expiring { color: @error_color; }
row.drop-above { box-shadow: inset 0 3px 0 0 @accent_color; }
row.drop-below { box-shadow: inset 0 -3px 0 0 @accent_color; }
.folder-tile { padding: 10px 6px; }
.folder-tile.drop-target { box-shadow: inset 0 0 0 2px @accent_color; }
.gen-value { font-family: monospace; font-size: 1.25em; font-weight: bold; }
.qr-frame { background: white; border-radius: 12px; padding: 6px; }
"""


def read_clipboard(widget, on_texts, on_error):
    """Lê a área de transferência: imagem → QR decodificado; texto → texto. Chama on_texts(list)."""
    clipboard = widget.get_clipboard()
    formats = clipboard.get_formats()

    def got_texture(cb, res):
        try:
            texture = cb.read_texture_finish(res)
            png = texture.save_to_png_bytes().get_data()
            img = cv2.imdecode(np.frombuffer(png, np.uint8), cv2.IMREAD_UNCHANGED)
        except GLib.Error:
            on_error("Não consegui ler a imagem da área de transferência.")
            return
        texts = decode_qr(img)
        if texts:
            on_texts(texts)
        else:
            on_error("Nenhum QR code encontrado no print. Tente recortar mais perto do QR.")

    def got_text(cb, res):
        try:
            text = cb.read_text_finish(res)
        except GLib.Error:
            text = None
        if text and text.strip():
            on_texts([text])
        else:
            on_error("A área de transferência está vazia.")

    if formats.contain_gtype(Gdk.Texture):
        clipboard.read_texture_async(None, got_texture)
    elif formats.contain_gtype(GObject.TYPE_STRING):
        clipboard.read_text_async(None, got_text)
    else:
        on_error("Copie um print do QR code (ou o código) antes de colar.")


def format_code(code):
    if len(code) == 6:
        return f"{code[:3]} {code[3:]}"
    if len(code) == 8:
        return f"{code[:4]} {code[4:]}"
    return code


class AccountRow(Adw.ActionRow):
    def __init__(self, window, acc, compact=False):
        """compact: só copiar + menu ⋮ (usado quando há 2 colunas e falta largura)."""
        super().__init__(use_markup=False, activatable=True)
        self.acc = acc
        self.remaining = acc["period"]
        self.set_title(acc["issuer"] or acc["name"] or "Sem nome")
        if acc["issuer"] and acc["name"]:
            self.set_subtitle(acc["name"])
        self.set_tooltip_text("Clique para copiar o código")

        self.code_label = Gtk.Label(css_classes=["otp-code", "numeric"])
        self.ring = Gtk.DrawingArea(content_width=22, content_height=22, valign=Gtk.Align.CENTER)
        self.ring.set_draw_func(self._draw_ring)
        copy_btn = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER,
                              css_classes=["flat"], tooltip_text="Copiar")
        copy_btn.connect("clicked", lambda *_: window.copy_code(self))
        if compact:
            more = Gtk.MenuButton(icon_name="view-more-symbolic", valign=Gtk.Align.CENTER,
                                  css_classes=["flat"], tooltip_text="Mais opções",
                                  menu_model=window.row_menu_for(acc))
            suffixes = (self.code_label, self.ring, copy_btn, more)
        else:
            more = Gtk.MenuButton(icon_name="view-more-symbolic", valign=Gtk.Align.CENTER,
                                  css_classes=["flat"], tooltip_text="QR code, remover…",
                                  menu_model=window.extra_menu_for(acc))
            folder_btn = Gtk.MenuButton(icon_name="folder-symbolic", valign=Gtk.Align.CENTER,
                                        css_classes=["flat"], tooltip_text="Mover para pasta",
                                        menu_model=window.folder_menu_for(acc))
            pinned = acc.get("pinned", False)
            pin_btn = Gtk.ToggleButton(icon_name="view-pin-symbolic", valign=Gtk.Align.CENTER,
                                       css_classes=["flat"], active=pinned,
                                       tooltip_text="Desafixar" if pinned else "Fixar no topo")
            pin_btn.connect("toggled", lambda b: window.set_pinned(acc, b.get_active()))
            suffixes = (self.code_label, self.ring, copy_btn, pin_btn, folder_btn, more)
        for w in suffixes:
            self.add_suffix(w)
        self.add_prefix(Gtk.Image(icon_name="list-drag-handle-symbolic", css_classes=["dim-label"],
                                  tooltip_text="Arraste para reordenar (ou Alt+↑/↓)"))
        self.connect("activated", lambda *_: window.copy_code(self))
        self._setup_reorder(window)
        self.refresh(time.time())

    def _setup_reorder(self, window):
        self._drag_offset = (0, 0)
        source = Gtk.DragSource(actions=Gdk.DragAction.MOVE)

        def prepare(_src, x, y):
            if window.search.get_text().strip():  # com busca a ordem visível é parcial
                return None
            self._drag_offset = (x, y)
            return Gdk.ContentProvider.new_for_value(DRAG_PREFIX + self.acc["id"])

        source.connect("prepare", prepare)
        source.connect("drag-begin", lambda _s, _d: _s.set_icon(
            Gtk.WidgetPaintable.new(self), *map(int, self._drag_offset)))
        self.add_controller(source)

        target = Gtk.DropTarget.new(GObject.TYPE_STRING, Gdk.DragAction.MOVE)

        def motion(_t, _x, y):
            below = y > self.get_height() / 2
            self.set_css_classes([c for c in self.get_css_classes()
                                  if c not in ("drop-above", "drop-below")]
                                 + ["drop-below" if below else "drop-above"])
            return Gdk.DragAction.MOVE

        def drop(_t, value, _x, y):
            self._clear_drop_marks()
            if not isinstance(value, str) or not value.startswith(DRAG_PREFIX):
                return False
            return window.move_account(value[len(DRAG_PREFIX):], self.acc, y > self.get_height() / 2)

        target.connect("motion", motion)
        target.connect("leave", lambda *_: self._clear_drop_marks())
        target.connect("drop", drop)
        self.add_controller(target)

        keys = Gtk.ShortcutController()
        for accel, delta in (("<Alt>Up", -1), ("<Alt>Down", 1)):
            keys.add_shortcut(Gtk.Shortcut.new(
                Gtk.ShortcutTrigger.parse_string(accel),
                Gtk.CallbackAction.new(lambda *_, d=delta: window.move_by(self.acc, d) or True)))
        self.add_controller(keys)

    def _clear_drop_marks(self):
        self.remove_css_class("drop-above")
        self.remove_css_class("drop-below")

    def current_code(self):
        return totp(self.acc)

    def refresh(self, now):
        period = self.acc["period"]
        self.remaining = period - (now % period)
        self.code_label.set_text(format_code(totp(self.acc, now)))
        if self.remaining <= 5:
            self.code_label.add_css_class("expiring")
        else:
            self.code_label.remove_css_class("expiring")
        self.ring.queue_draw()

    def _draw_ring(self, area, cr, w, h):
        color = area.get_color()
        frac = self.remaining / self.acc["period"]
        r = min(w, h) / 2 - 2.5
        cr.set_line_width(3)
        cr.set_source_rgba(color.red, color.green, color.blue, 0.15)
        cr.arc(w / 2, h / 2, r, 0, 2 * math.pi)
        cr.stroke()
        if self.remaining <= 5:
            cr.set_source_rgba(0.88, 0.11, 0.14, 1)
        else:
            cr.set_source_rgba(color.red, color.green, color.blue, 0.8)
        cr.arc(w / 2, h / 2, r, -math.pi / 2, -math.pi / 2 + 2 * math.pi * frac)
        cr.stroke()


class AddDialog(Adw.Dialog):
    def __init__(self, window):
        super().__init__(title="Adicionar conta", content_width=480)
        self.window = window
        self._filling = False

        self.toasts = Adw.ToastOverlay()
        view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        self.add_btn = Gtk.Button(label="Adicionar", css_classes=["suggested-action"], sensitive=False)
        self.add_btn.connect("clicked", self.on_add)
        header.pack_end(self.add_btn)
        view.add_top_bar(header)

        page = Adw.PreferencesPage()
        qr = Adw.PreferencesGroup(
            title="Pelo QR code",
            description="Tire um print do QR code (Print Screen) e cole aqui com Ctrl+V.")
        paste_row = Adw.ButtonRow(title="Colar print do QR code", start_icon_name="edit-paste-symbolic")
        paste_row.connect("activated", lambda *_: self.paste())
        file_row = Adw.ButtonRow(title="Abrir imagem…", start_icon_name="document-open-symbolic")
        file_row.connect("activated", lambda *_: self.open_file())
        qr.add(paste_row)
        qr.add(file_row)
        page.add(qr)

        manual = Adw.PreferencesGroup(
            title="Ou digite o código",
            description="Use a chave de configuração que o site mostra em “não consigo ler o QR code”.")
        self.secret_row = Adw.EntryRow(title="Chave secreta ou link otpauth://")
        self.secret_row.connect("changed", self.on_secret_changed)
        self.secret_row.connect("entry-activated", self.on_add)
        self.issuer_row = Adw.EntryRow(title="Serviço (ex.: GitHub, Google)")
        self.issuer_row.connect("entry-activated", self.on_add)
        self.name_row = Adw.EntryRow(title="Conta (ex.: seu@email.com)")
        self.name_row.connect("entry-activated", self.on_add)
        for r in (self.secret_row, self.issuer_row, self.name_row):
            manual.add(r)
        self.folder_ids = [""] + [f["id"] for f in window.vault.folders]
        self.folder_row = Adw.ComboRow(
            title="Pasta", visible=len(self.folder_ids) > 1,
            model=Gtk.StringList.new(["Sem pasta"] + [f["name"] for f in window.vault.folders]))
        if window.current_folder in self.folder_ids:  # pasta aberta na janela vem pré-selecionada
            self.folder_row.set_selected(self.folder_ids.index(window.current_folder))
        manual.add(self.folder_row)

        adv = Adw.ExpanderRow(title="Avançado", subtitle="Só mude se o site pedir")
        self.algo_row = Adw.ComboRow(title="Algoritmo", model=Gtk.StringList.new(list(ALGORITHMS)))
        self.digits_row = Adw.SpinRow.new_with_range(6, 8, 1)
        self.digits_row.set_title("Dígitos")
        self.digits_row.set_value(6)
        self.period_row = Adw.SpinRow.new_with_range(10, 120, 5)
        self.period_row.set_title("Período (segundos)")
        self.period_row.set_value(30)
        for r in (self.algo_row, self.digits_row, self.period_row):
            adv.add_row(r)
        manual.add(adv)
        page.add(manual)

        view.set_content(page)
        self.toasts.set_child(view)
        self.set_child(self.toasts)

        keys = Gtk.ShortcutController()
        keys.add_shortcut(Gtk.Shortcut.new(Gtk.ShortcutTrigger.parse_string("<Control>v"),
                                           Gtk.CallbackAction.new(self._shortcut_paste)))
        self.add_controller(keys)

    def _shortcut_paste(self, *_):
        focus = self.get_focus()
        if isinstance(focus, Gtk.Text):  # deixa colar texto normalmente nos campos
            return False
        self.paste()
        return True

    def toast(self, msg):
        self.toasts.add_toast(Adw.Toast(title=msg, timeout=4))

    def paste(self):
        read_clipboard(self, self.handle_texts, self.toast)

    def open_file(self):
        filters = Gio.ListStore.new(Gtk.FileFilter)
        f = Gtk.FileFilter(name="Imagens")
        f.add_mime_type("image/*")
        filters.append(f)
        dialog = Gtk.FileDialog(title="Imagem com QR code", filters=filters)
        pictures = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_PICTURES)
        if pictures:
            dialog.set_initial_folder(Gio.File.new_for_path(pictures))

        def done(d, res):
            try:
                file = d.open_finish(res)
            except GLib.Error:
                return
            ok, data, _ = file.load_contents(None)
            img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_UNCHANGED) if ok else None
            texts = decode_qr(img)
            if texts:
                self.handle_texts(texts)
            else:
                self.toast("Nenhum QR code encontrado nessa imagem.")

        dialog.open(self.window, None, done)

    def handle_texts(self, texts):
        try:
            accounts = []
            for t in texts:
                parsed = parse_payload(t)
                if parsed is None:
                    if len(texts) == 1 and not t.lower().startswith(("http", "otpauth")):
                        self.secret_row.set_text(t.strip())  # texto colado: trata como chave
                        return
                    raise ParseError("Esse QR code não é de autenticação em 2 etapas.")
                accounts.extend(parsed)
        except ParseError as e:
            self.toast(str(e))
            return
        if len(accounts) == 1:
            self.fill(accounts[0])
            self.toast("QR code lido! Confira os dados e clique em Adicionar.")
        else:
            self.window.add_accounts(self._in_folder(accounts))
            self.close()

    def _in_folder(self, accounts):
        fid = self.folder_ids[self.folder_row.get_selected()]
        for acc in accounts:
            if fid:
                acc["folder"] = fid
        return accounts

    def fill(self, acc):
        self._filling = True
        self.secret_row.set_text(acc["secret"])
        self.issuer_row.set_text(acc["issuer"])
        self.name_row.set_text(acc["name"])
        self.algo_row.set_selected(list(ALGORITHMS).index(acc["algorithm"]))
        self.digits_row.set_value(acc["digits"])
        self.period_row.set_value(acc["period"])
        self._filling = False
        self.on_secret_changed(self.secret_row)

    def on_secret_changed(self, row):
        if self._filling:
            return
        text = row.get_text().strip()
        if text.lower().startswith("otpauth"):
            GLib.idle_add(self.handle_texts, [text])
            return
        try:
            make_account(text)
            ok = True
        except ParseError:
            ok = False
        self.add_btn.set_sensitive(ok)
        if text and not ok:
            row.add_css_class("error")
        else:
            row.remove_css_class("error")

    def on_add(self, *_):
        if not self.add_btn.get_sensitive():
            return
        try:
            acc = make_account(self.secret_row.get_text(), self.issuer_row.get_text(),
                               self.name_row.get_text(),
                               list(ALGORITHMS)[self.algo_row.get_selected()],
                               int(self.digits_row.get_value()), int(self.period_row.get_value()))
        except ParseError as e:
            self.toast(str(e))
            return
        if not acc["issuer"] and not acc["name"]:
            self.toast("Dê um nome ao serviço para reconhecer depois.")
            self.issuer_row.grab_focus()
            return
        self.window.add_accounts(self._in_folder([acc]))
        self.close()


class GenRow(Adw.ActionRow):
    """Linha do gerador: valor, gerar outro e copiar (clicar na linha também copia)."""

    def __init__(self, title, fmt, on_generate, on_copy, extra=()):
        super().__init__(title=title, activatable=True, use_markup=False,
                         tooltip_text="Clique para copiar")
        self.raw = ""
        self.fmt = fmt  # raw → texto com pontuação
        self.formatted = True
        self.value_label = Gtk.Label(css_classes=["gen-value", "numeric"])
        regen = Gtk.Button(icon_name="view-refresh-symbolic", valign=Gtk.Align.CENTER,
                           css_classes=["flat"], tooltip_text="Gerar outro")
        regen.connect("clicked", lambda *_: on_generate())
        copy_btn = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER,
                              css_classes=["flat"], tooltip_text="Copiar")
        copy_btn.connect("clicked", lambda *_: on_copy())
        for w in (self.value_label, regen, copy_btn, *extra):
            self.add_suffix(w)
        self.connect("activated", lambda *_: on_copy())

    @property
    def value(self):
        return self.fmt(self.raw) if self.formatted and self.raw else self.raw

    def set_raw(self, raw):
        self.raw = raw
        self.value_label.set_text(self.value)

    def set_formatted(self, formatted):
        self.formatted = formatted
        self.value_label.set_text(self.value)


class GeneratorPage(Adw.Bin):
    """Aba Gerador: CPF, CNPJ e CEP válidos para testes. Não depende do cofre."""

    def __init__(self, window):
        super().__init__()
        self.window = window
        self.settings = window.settings
        self.started = False
        self.cep_pool = {}  # UF → endereços reais do ViaCEP ainda não usados
        self.cep_entry = None  # endereço do CEP exibido (None = não verificado)
        self._cep_req = 0  # descarta respostas atrasadas do ViaCEP
        self._check_req = 0

        view = Adw.ToolbarView()
        header = Adw.HeaderBar(title_widget=Adw.WindowTitle(title="Gerador",
                                                            subtitle="Dados válidos para testes"))
        regen_all = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Gerar todos (Ctrl+R)")
        regen_all.connect("clicked", lambda *_: self.generate_all())
        header.pack_start(regen_all)
        view.add_top_bar(header)
        page = Adw.PreferencesPage()

        gen = Adw.PreferencesGroup(title="Gerar", description="Clique numa linha para copiar.")
        self.cpf_row = GenRow("CPF", format_cpf, self.new_cpf,
                              lambda: self.copy(self.cpf_row, self.new_cpf))
        self.cnpj_row = GenRow("CNPJ", format_cnpj, self.new_cnpj,
                               lambda: self.copy(self.cnpj_row, self.new_cnpj))
        self.addr_btn = Gtk.Button(icon_name="mark-location-symbolic", valign=Gtk.Align.CENTER,
                                   css_classes=["flat"], sensitive=False,
                                   tooltip_text="Copiar endereço completo")
        self.addr_btn.connect("clicked", lambda *_: self.copy_address())
        self.cep_row = GenRow("CEP", format_cep, self.new_cep,
                              lambda: self.copy(self.cep_row, self.new_cep), extra=(self.addr_btn,))
        for r in self.rows:
            r.set_formatted(self.settings["gen_formatted"])
            gen.add(r)
        page.add(gen)

        opts = Adw.PreferencesGroup(title="Opções")
        opts.add(self._switch("Com pontuação", "Ex.: 123.456.789-09. Desligado: só os números.",
                              "gen_formatted",
                              lambda v: [r.set_formatted(v) for r in self.rows]))
        opts.add(self._switch("CNPJ alfanumérico",
                              "Formato novo da Receita, com letras na raiz (a partir de julho/2026).",
                              "gen_cnpj_alnum", lambda _v: self.new_cnpj()))
        self._ufs = [""] + sorted(CEP_RANGES)
        uf_row = Adw.ComboRow(title="Estado do CEP",
                              model=Gtk.StringList.new(["Qualquer"] + self._ufs[1:]))
        uf_row.set_selected(self._ufs.index(self.settings["gen_cep_uf"]))
        uf_row.connect("notify::selected", lambda r, _p: self._set(
            "gen_cep_uf", self._ufs[r.get_selected()], lambda _v: self.new_cep()))
        opts.add(uf_row)
        opts.add(self._switch("CEP real", "Consulta o ViaCEP (precisa de internet) e traz o endereço. "
                                          "Desligado: só formato e faixa do estado.",
                              "gen_cep_real", lambda _v: self.new_cep()))
        opts.add(self._switch("Gerar outro ao copiar", "Para preencher vários cadastros seguidos.",
                              "gen_new_after_copy", None))
        page.add(opts)

        batch = Adw.PreferencesGroup(title="Em lote",
                                     description="Valores diferentes, um por linha, direto para a "
                                                 "área de transferência.")
        self.qty_row = Adw.SpinRow.new_with_range(2, 1000, 1)
        self.qty_row.set_title("Quantidade")
        self.qty_row.set_value(10)
        self.batch_cpf = Adw.ButtonRow(start_icon_name="edit-copy-symbolic")
        self.batch_cpf.connect("activated", lambda *_: self.copy_batch("CPFs", generate_cpf, format_cpf))
        self.batch_cnpj = Adw.ButtonRow(start_icon_name="edit-copy-symbolic")
        self.batch_cnpj.connect("activated", lambda *_: self.copy_batch(
            "CNPJs", lambda: generate_cnpj(self.settings["gen_cnpj_alnum"]), format_cnpj))
        self.qty_row.connect("notify::value", lambda *_: self._update_batch_titles())
        self._update_batch_titles()
        for r in (self.qty_row, self.batch_cpf, self.batch_cnpj):
            batch.add(r)
        page.add(batch)

        check = Adw.PreferencesGroup(title="Validar",
                                     description="Cole um CPF, CNPJ ou CEP, com ou sem pontuação.")
        self.check_entry = Adw.EntryRow(title="CPF, CNPJ ou CEP")
        self.check_entry.connect("changed", self.on_check)
        self.check_result = Adw.ActionRow(use_markup=False, visible=False)
        self.check_icon = Gtk.Image()
        self.check_result.add_prefix(self.check_icon)
        check.add(self.check_entry)
        check.add(self.check_result)
        page.add(check)

        view.set_content(page)
        self.set_child(view)

    @property
    def rows(self):
        return (self.cpf_row, self.cnpj_row, self.cep_row)

    def _switch(self, title, subtitle, key, on_change):
        row = Adw.SwitchRow(title=title, subtitle=subtitle, active=self.settings[key])
        row.connect("notify::active", lambda r, _p: self._set(key, r.get_active(), on_change))
        return row

    def _set(self, key, value, on_change):
        if self.settings[key] == value:
            return
        self.settings.set(key, value)
        if on_change:
            on_change(value)

    def start(self):
        """Gera os valores na primeira vez que a aba aparece (o CEP real usa a rede)."""
        if not self.started:
            self.started = True
            self.generate_all()

    def generate_all(self):
        self.new_cpf()
        self.new_cnpj()
        self.new_cep()

    def new_cpf(self):
        self.cpf_row.set_raw(generate_cpf())

    def new_cnpj(self):
        self.cnpj_row.set_raw(generate_cnpj(self.settings["gen_cnpj_alnum"]))

    def new_cep(self):
        uf = self.settings["gen_cep_uf"] or _rng.choice(sorted(CEP_RANGES))
        self._cep_req += 1
        req = self._cep_req
        if not self.settings["gen_cep_real"]:
            self._show_cep(random_cep(uf), None, f"Formato e faixa válidos para {uf} (pode não existir)")
            return
        if self.cep_pool.get(uf):
            self._show_cep_entry(uf, self.cep_pool[uf].pop())
            return
        self.cep_row.set_subtitle(f"Buscando um endereço real em {UF_CAPITALS[uf]}/{uf}…")

        def work():
            try:
                result = fetch_real_ceps(uf)
            except Exception as e:  # rede, JSON ou HTTP: cai no CEP só com formato
                result = e
            GLib.idle_add(self._on_real_ceps, req, uf, result)

        threading.Thread(target=work, daemon=True).start()

    def _on_real_ceps(self, req, uf, result):
        if isinstance(result, list) and result:
            _rng.shuffle(result)
            self.cep_pool[uf] = result
            if req == self._cep_req:
                self._show_cep_entry(uf, result.pop())
        elif req == self._cep_req:
            why = "Sem conexão com o ViaCEP" if isinstance(result, Exception) else "O ViaCEP não achou endereços"
            self._show_cep(random_cep(uf), None, f"{why}: CEP só com formato válido para {uf}")
        return GLib.SOURCE_REMOVE

    def _show_cep_entry(self, uf, entry):
        raw = _only_digits(str(entry.get("cep", "")))
        if len(raw) != 8:
            self._show_cep(random_cep(uf), None, f"Formato e faixa válidos para {uf} (pode não existir)")
            return
        self._show_cep(raw, entry, format_address(entry))

    def _show_cep(self, raw, entry, subtitle):
        self.cep_entry = entry
        self.cep_row.set_raw(raw)
        self.cep_row.set_subtitle(subtitle)
        self.addr_btn.set_sensitive(entry is not None)

    def copy(self, row, regen):
        if not row.raw:
            return
        value = row.value
        self.window.get_clipboard().set(value)
        self.window.toast(f"{row.get_title()} {value} copiado")
        if self.settings["gen_new_after_copy"]:
            regen()

    def copy_address(self):
        if self.cep_entry:
            self.window.get_clipboard().set(full_address(self.cep_entry))
            self.window.toast("Endereço completo copiado")

    def _update_batch_titles(self):
        n = int(self.qty_row.get_value())
        self.batch_cpf.set_title(f"Copiar {n} CPFs")
        self.batch_cnpj.set_title(f"Copiar {n} CNPJs")

    def copy_batch(self, label, generate, fmt):
        n = int(self.qty_row.get_value())
        values = {}  # dict: sem repetidos e na ordem gerada
        while len(values) < n:
            values[generate()] = None
        formatted = self.settings["gen_formatted"]
        self.window.get_clipboard().set("\n".join(fmt(v) if formatted else v for v in values))
        self.window.toast(f"{n} {label} copiados, um por linha")

    def on_check(self, entry):
        self._check_req += 1
        text = entry.get_text()
        result = check_document(text)
        if result is None:
            self.check_result.set_visible(False)
            return
        kind, ok, msg = result
        self.check_icon.set_from_icon_name("object-select-symbolic" if ok else "dialog-error-symbolic")
        self.check_icon.set_css_classes(["success"] if ok else ["error"])
        self.check_result.set_title(msg)
        self.check_result.set_subtitle("")
        self.check_result.set_visible(True)
        if kind == "CEP" and ok and self.settings["gen_cep_real"]:
            req, cep = self._check_req, _only_digits(text)
            self.check_result.set_subtitle("Consultando o ViaCEP…")

            def work():
                try:
                    found = lookup_cep(cep)
                except Exception as e:
                    found = e
                GLib.idle_add(self._on_check_cep, req, found)

            threading.Thread(target=work, daemon=True).start()

    def _on_check_cep(self, req, found):
        if req == self._check_req:
            if isinstance(found, Exception):
                self.check_result.set_subtitle("Sem conexão com o ViaCEP para conferir se existe.")
            elif found is None:
                self.check_icon.set_from_icon_name("dialog-warning-symbolic")
                self.check_icon.set_css_classes(["warning"])
                self.check_result.set_subtitle("Formato certo, mas esse CEP não existe no ViaCEP.")
            else:
                self.check_result.set_subtitle("Existe: " + format_address(found))
        return GLib.SOURCE_REMOVE


class Window(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Autenticador", default_width=500, default_height=660)
        self.vault = Vault()
        self.rows = []
        self.fp = Fingerprint()
        self.fp_unlock_enabled = False  # há chave no chaveiro para este cofre
        self.fp_gave_up = False  # esgotou tentativas na tela de bloqueio

        self.fp_action = Gio.SimpleAction.new_stateful("fingerprint", None, GLib.Variant.new_boolean(False))
        self.fp_action.connect("activate", self.on_toggle_fingerprint)
        self.add_action(self.fp_action)

        self.settings = Settings()
        self.current_folder = None  # None = tela inicial; ou id da pasta aberta
        for name, ptype, cb in (("move-to-folder", "(ss)", self.on_move_to_folder),
                                ("new-folder", "s", self.on_new_folder),
                                ("rename-folder", None, self.on_rename_folder),
                                ("delete-folder", None, self.on_delete_folder),
                                ("toggle-pin", "s", self.on_toggle_pin),
                                ("delete-account", "s", self.on_delete_account),
                                ("show-qr", "s", self.on_show_qr),
                                ("change-password", None, self.on_change_password),
                                ("export-backup", None, self.on_export_backup),
                                ("import-backup", None, self.on_import_backup),
                                ("preferences", None, self.open_preferences)):
            action = Gio.SimpleAction.new(name, GLib.VariantType.new(ptype) if ptype else None)
            action.connect("activate", cb)
            self.add_action(action)

        self.toasts = Adw.ToastOverlay()
        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.stack.add_named(self._build_lock_page(), "lock")
        self.stack.add_named(self._build_main_page(), "main")
        # abas: Códigos (cofre) e Gerador (não precisa desbloquear)
        self.generator = GeneratorPage(self)
        self.views = Adw.ViewStack()
        self.views.add_titled_with_icon(self.stack, "codes", "Códigos", "dialog-password-symbolic")
        self.views.add_titled_with_icon(self.generator, "generator", "Gerador",
                                        "applications-engineering-symbolic")
        self.views.connect("notify::visible-child-name", lambda *_: self._on_view_changed())
        outer = Adw.ToolbarView(content=self.views)
        outer.add_bottom_bar(Adw.ViewSwitcherBar(stack=self.views, reveal=True))
        self.toasts.set_child(outer)
        self.set_content(self.toasts)

        keys = Gtk.ShortcutController()
        for accel, cb in (("<Control>v", self._shortcut_paste), ("<Control>n", self._shortcut_add),
                          ("<Control>l", self._shortcut_lock), ("Escape", self._shortcut_back),
                          ("<Control>1", lambda *_: self.views.set_visible_child_name("codes") or True),
                          ("<Control>2", lambda *_: self.views.set_visible_child_name("generator") or True),
                          ("<Control>r", self._shortcut_regenerate)):
            keys.add_shortcut(Gtk.Shortcut.new(Gtk.ShortcutTrigger.parse_string(accel),
                                               Gtk.CallbackAction.new(cb)))
        self.add_controller(keys)

        # só segura o leitor enquanto a janela está em foco, para não travar o sudo/login
        self.connect("notify::is-active", lambda *_: self._update_fp_unlock())
        self.connect("close-request", lambda *_: self.fp.stop() or False)

        self._inactive_since = None  # desde quando a janela está sem foco (bloqueio automático)
        self._watch_screen_lock()
        keyring_migrate_legacy()
        self.show_lock()
        GLib.timeout_add(500, self._tick)

    def _on_codes(self):
        return self.views.get_visible_child_name() == "codes"

    def _on_view_changed(self):
        if self._on_codes():
            if self.stack.get_visible_child_name() == "lock":
                self.pw_row.grab_focus()
        else:
            self.generator.start()
        self._update_fp_unlock()

    # --- bloqueio automático

    def _watch_screen_lock(self):
        """Bloqueia o cofre junto com a tela do computador e antes de suspender."""
        def on_lock(*_):
            if self.settings["lock_on_screen_lock"]:
                self.lock()

        def on_active(_c, _s, _p, _i, _m, params):
            if params.unpack()[0]:
                on_lock()

        def on_sleep(_c, _s, _p, _i, _m, params):
            if params.unpack()[0]:  # True = indo suspender
                on_lock()

        none = Gio.DBusSignalFlags.NONE
        try:
            session = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            # GNOME (gnome-shell) e KDE/outros emitem ActiveChanged(true) ao bloquear a tela
            for iface in ("org.gnome.ScreenSaver", "org.freedesktop.ScreenSaver"):
                session.signal_subscribe(None, iface, "ActiveChanged", None, None, none, on_active)
        except GLib.Error:
            pass
        try:
            system = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
            try:  # só a sessão deste usuário (loginctl lock-session)
                path = system.call_sync(
                    "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
                    "GetSessionByPID", GLib.Variant("(u)", (os.getpid(),)), GLib.VariantType.new("(o)"),
                    Gio.DBusCallFlags.NONE, 3000, None).unpack()[0]
            except GLib.Error:
                path = None
            system.signal_subscribe("org.freedesktop.login1", "org.freedesktop.login1.Session", "Lock",
                                    path, None, none, on_lock)
            system.signal_subscribe("org.freedesktop.login1", "org.freedesktop.login1.Manager",
                                    "PrepareForSleep", "/org/freedesktop/login1", None, none, on_sleep)
        except GLib.Error:
            pass

    def _check_idle_lock(self):
        minutes = self.settings["auto_lock_minutes"]
        if not self.vault.unlocked or not minutes or self.is_active():
            self._inactive_since = None
            return
        now = time.monotonic()
        if self._inactive_since is None:
            self._inactive_since = now
        elif now - self._inactive_since >= minutes * 60:
            self.lock()

    # --- páginas

    def _build_lock_page(self):
        view = Adw.ToolbarView()
        view.add_top_bar(Adw.HeaderBar(show_title=False))
        self.lock_status = Adw.StatusPage(icon_name="channel-secure-symbolic", css_classes=["compact"])
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        group = Adw.PreferencesGroup()
        self.pw_row = Adw.PasswordEntryRow(title="Senha mestra")
        self.pw_row.connect("entry-activated", self.on_unlock)
        self.pw2_row = Adw.PasswordEntryRow(title="Confirmar senha")
        self.pw2_row.connect("entry-activated", self.on_unlock)
        group.add(self.pw_row)
        group.add(self.pw2_row)
        self.lock_error = Gtk.Label(css_classes=["error"], wrap=True, visible=False)
        self.unlock_btn = Gtk.Button(css_classes=["suggested-action", "pill"], halign=Gtk.Align.CENTER)
        self.unlock_btn.connect("clicked", self.on_unlock)

        self.fp_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, visible=False)
        self.fp_box.append(Gtk.Image(icon_name="auth-fingerprint-symbolic", pixel_size=36,
                                     css_classes=["dim-label"]))
        self.fp_label = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER)
        self.fp_box.append(self.fp_label)
        self.fp_retry_btn = Gtk.Button(label="Tentar a digital de novo", css_classes=["flat"],
                                       halign=Gtk.Align.CENTER, visible=False)
        self.fp_retry_btn.connect("clicked", self._retry_fp_unlock)
        self.fp_box.append(self.fp_retry_btn)

        for w in (self.fp_box, group, self.lock_error, self.unlock_btn):
            box.append(w)
        self.lock_status.set_child(Adw.Clamp(maximum_size=360, child=box))
        view.set_content(self.lock_status)
        return view

    def _build_main_page(self):
        view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        self.title_widget = Adw.WindowTitle(title="Autenticador")
        header.set_title_widget(self.title_widget)
        self.back_btn = Gtk.Button(icon_name="go-previous-symbolic", tooltip_text="Voltar (Esc)", visible=False)
        self.back_btn.connect("clicked", lambda *_: self.open_folder(None))
        add_btn = Gtk.Button(icon_name="list-add-symbolic", tooltip_text="Adicionar conta (Ctrl+N)")
        add_btn.connect("clicked", lambda *_: self.open_add_dialog())
        paste_btn = Gtk.Button(icon_name="edit-paste-symbolic", tooltip_text="Colar print do QR code (Ctrl+V)")
        paste_btn.connect("clicked", lambda *_: self.paste_direct())
        folder_btn = Gtk.Button(icon_name="folder-new-symbolic", tooltip_text="Nova pasta",
                                action_name="win.new-folder", action_target=GLib.Variant("s", ""))
        lock_btn = Gtk.Button(icon_name="system-lock-screen-symbolic", tooltip_text="Bloquear (Ctrl+L)")
        lock_btn.connect("clicked", lambda *_: self.lock())
        general = Gio.Menu()
        general.append("Preferências", "win.preferences")
        general.append("Desbloquear com digital", "win.fingerprint")
        general.append("Trocar senha mestra…", "win.change-password")
        folders = Gio.Menu()
        folders.append_item(self._menu_item("Nova pasta…", "win.new-folder", GLib.Variant("s", "")))
        folders.append("Renomear esta pasta…", "win.rename-folder")
        folders.append("Excluir esta pasta…", "win.delete-folder")
        backup = Gio.Menu()
        backup.append("Exportar backup…", "win.export-backup")
        backup.append("Importar backup…", "win.import-backup")
        menu = Gio.Menu()
        menu.append_section(None, general)
        menu.append_section("Pastas", folders)
        menu.append_section("Backup", backup)
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu, tooltip_text="Menu")
        header.pack_start(self.back_btn)
        header.pack_start(add_btn)
        header.pack_start(paste_btn)
        header.pack_start(folder_btn)
        header.pack_end(menu_btn)
        header.pack_end(lock_btn)
        view.add_top_bar(header)

        self.search = Gtk.SearchEntry(placeholder_text="Buscar", hexpand=True)
        self.search.connect("search-changed", lambda *_: self.rebuild_list())
        self.search.connect("stop-search", lambda *_: self.open_folder(None))
        # cartões das pastas (só na tela inicial)
        self.folders_flow = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, homogeneous=True,
                                        column_spacing=12, row_spacing=12, visible=False)
        self.groups_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                           margin_top=12, margin_bottom=24, margin_start=12, margin_end=12)
        list_box.append(self.search)
        list_box.append(self.folders_flow)
        list_box.append(self.groups_box)
        hint = Gtk.Label(label="Clique numa conta para copiar o código; arraste para reordenar "
                               "ou solte numa pasta.  Ctrl+V cola um print de QR code.",
                         css_classes=["dim-label", "caption"], wrap=True)
        list_box.append(hint)
        self.clamp = Adw.Clamp(maximum_size=560, child=list_box)
        scrolled = Gtk.ScrolledWindow(vexpand=True, child=self.clamp)

        empty = Adw.StatusPage(
            icon_name="dialog-password-symbolic", title="Nenhuma conta ainda",
            description="Tire um print do QR code de 2FA e aperte Ctrl+V aqui,\n"
                        "ou adicione digitando a chave secreta.")
        empty_btns = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER)
        b1 = Gtk.Button(label="Colar print do QR", css_classes=["suggested-action", "pill"])
        b1.connect("clicked", lambda *_: self.paste_direct())
        b2 = Gtk.Button(label="Digitar chave", css_classes=["pill"])
        b2.connect("clicked", lambda *_: self.open_add_dialog())
        empty_btns.append(b1)
        empty_btns.append(b2)
        empty.set_child(empty_btns)

        self.content_stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.content_stack.add_named(empty, "empty")
        self.content_stack.add_named(scrolled, "list")
        view.set_content(self.content_stack)
        return view

    # --- bloqueio

    def show_lock(self):
        first = not Vault.exists()
        self.lock_status.set_title("Criar cofre" if first else "Autenticador bloqueado")
        self.lock_status.set_description(
            "Crie uma senha mestra. Ela protege suas chaves 2FA e não pode ser recuperada."
            if first else "Digite sua senha mestra.")
        self.pw2_row.set_visible(first)
        self.unlock_btn.set_label("Criar" if first else "Desbloquear")
        self.pw_row.set_text("")
        self.pw2_row.set_text("")
        self.lock_error.set_visible(False)
        self.stack.set_visible_child_name("lock")
        self.pw_row.grab_focus()
        self.fp_unlock_enabled = not first and keyring_has_key()
        self.fp_gave_up = False
        self.fp_box.set_visible(self.fp_unlock_enabled)
        self._update_fp_unlock()

    # --- digital

    def _update_fp_unlock(self):
        """Liga/desliga a leitura na tela de bloqueio conforme foco e estado."""
        want = (self.fp_unlock_enabled and not self.fp_gave_up and self.is_active()
                and self._on_codes() and self.stack.get_visible_child_name() == "lock")
        if want and not self.fp.running:
            self.fp_label.set_label("Encoste o dedo no leitor ou digite a senha.")
            self.fp_retry_btn.set_visible(False)
            self.fp.start(self._on_fp_unlock)
        elif not want and self.fp.running and self.stack.get_visible_child_name() == "lock":
            self.fp.stop()

    def _retry_fp_unlock(self, *_):
        self.fp_gave_up = False
        self._update_fp_unlock()

    def _on_fp_unlock(self, kind, message):
        if kind == "status":
            self.fp_label.set_label(message)
            return
        if kind == "error":
            self.fp_gave_up = True
            self.fp_label.set_label(message)
            self.fp_retry_btn.set_visible(True)
            return
        try:
            key = keyring_load_key()
            if key is None:
                raise InvalidTag
            self.vault.unlock_with_key(key)
        except InvalidTag:
            keyring_clear_key()
            self.fp_unlock_enabled = False
            self.fp_box.set_visible(False)
            return self._lock_fail("A digital foi desativada porque o cofre mudou. Use a senha mestra.")
        except (GLib.Error, OSError, ValueError, KeyError) as e:
            self.fp_gave_up = True
            self.fp_retry_btn.set_visible(True)
            return self._lock_fail(f"Erro ao abrir o cofre pela digital: {e}")
        self._enter_main()

    def on_toggle_fingerprint(self, action, _param):
        if not self.vault.unlocked:
            return
        if self.fp.running:  # clicou de novo enquanto esperava o dedo: cancela
            self.fp.stop()
            self.toast("Ativação da digital cancelada.")
            return
        if action.get_state().get_boolean():
            keyring_clear_key()
            action.set_state(GLib.Variant.new_boolean(False))
            self.toast("Desbloqueio com digital desativado.")
            return
        if not Fingerprint.available():
            self.toast("Nenhuma digital cadastrada. Cadastre com: fprintd-enroll", 5)
            return

        def on_result(kind, message):
            if kind == "status":
                self.toast(message)
            elif kind == "error":
                self.toast(message, 5)
            elif self.vault.unlocked:
                try:
                    keyring_store_key(self.vault.key)
                except GLib.Error as e:
                    self.toast(f"Não consegui salvar no chaveiro: {e.message}", 5)
                    return
                action.set_state(GLib.Variant.new_boolean(True))
                self.toast("Desbloqueio com digital ativado ✓")

        self.toast("Encoste o dedo no leitor para ativar.", 6)
        self.fp.start(on_result)

    def _lock_fail(self, msg):
        self.lock_error.set_label(msg)
        self.lock_error.set_visible(True)

    def on_unlock(self, *_):
        pw = self.pw_row.get_text()
        if not Vault.exists():
            if len(pw) < 6:
                return self._lock_fail("Use pelo menos 6 caracteres.")
            if pw != self.pw2_row.get_text():
                return self._lock_fail("As senhas não conferem.")
            self.vault.create(pw)
        else:
            try:
                self.vault.unlock(pw)
            except InvalidTag:
                self.pw_row.set_text("")
                return self._lock_fail("Senha incorreta.")
            except (OSError, ValueError, KeyError) as e:
                return self._lock_fail(f"Erro ao abrir o cofre: {e}")
        self._enter_main()

    def _enter_main(self):
        self.fp.stop()
        self.pw_row.set_text("")
        self.pw2_row.set_text("")
        self.fp_action.set_state(GLib.Variant.new_boolean(keyring_has_key()))
        self._inactive_since = None
        self.rebuild_list()
        self.stack.set_visible_child_name("main")

    def lock(self):
        if self.vault.unlocked:
            self.fp.stop()
            # fecha diálogos abertos (QR code, adicionar…), que podem mostrar segredos
            for _ in range(10):
                dialog = self.get_visible_dialog()
                if dialog is None:
                    break
                dialog.force_close()
            self.vault.lock()
            self.rebuild_list()
            self.show_lock()

    # --- lista

    def display_order(self):
        # fixados no topo; dentro de cada grupo vale a ordem do cofre (sort estável)
        return sorted(self.vault.accounts, key=lambda a: not a.get("pinned", False))

    def open_folder(self, fid):
        """Entra na pasta (fid) ou volta para a tela inicial (None)."""
        if fid == self.current_folder:
            return
        self.current_folder = fid
        self.search.set_text("")
        self.rebuild_list()

    def rebuild_list(self, focus_id=None):
        for box in (self.groups_box, self.folders_flow):
            while (child := box.get_first_child()) is not None:
                box.remove(child)
        self.rows = []
        folder = self._current_folder_obj()
        if folder is None:
            self.current_folder = None  # pasta aberta deixou de existir
        q = self.search.get_text().strip().lower()
        in_folder = folder is not None

        self.title_widget.set_title(folder["name"] if in_folder else "Autenticador")
        self.back_btn.set_visible(in_folder)
        for name in ("rename-folder", "delete-folder"):
            self.lookup_action(name).set_enabled(in_folder)
        cols = self.settings["code_columns"]
        self.clamp.set_maximum_size(560 * cols)

        show_tiles = not in_folder and not q and bool(self.vault.folders)
        if show_tiles:
            per_row = self.settings["folders_per_row"]
            self.folders_flow.set_min_children_per_line(per_row)
            self.folders_flow.set_max_children_per_line(per_row)
            for f in self.vault.folders:
                self.folders_flow.append(self._folder_tile(f))
        self.folders_flow.set_visible(show_tiles)

        accs = self.display_order()
        if in_folder:
            accs = [a for a in accs if a.get("folder") == folder["id"]]
        elif not q and not self.settings["home_shows_folder_codes"]:
            accs = [a for a in accs if not a.get("folder")]  # códigos das pastas só dentro delas
        if q:
            accs = [a for a in accs if q in f"{a['issuer']} {a['name']}".lower()]

        grouped = not in_folder and self.vault.folders and (q or self.settings["home_shows_folder_codes"])
        if grouped:
            buckets = [("", "Sem pasta")] + [(f["id"], f["name"]) for f in self.vault.folders]
            buckets = [(title, [a for a in accs if a.get("folder", "") == fid]) for fid, title in buckets]
        else:
            buckets = [("", accs)]
        for title, group_accs in buckets:
            if group_accs:
                self.groups_box.append(self._build_group(title, group_accs, focus_id))
        if not self.rows:
            msg = None
            if q:
                msg = "Nada encontrado."
            elif in_folder:
                msg = "Nenhuma conta nesta pasta. O + adiciona contas aqui."
            if msg:
                self.groups_box.append(Gtk.Label(label=msg, css_classes=["dim-label"], wrap=True, margin_top=24))
        self.content_stack.set_visible_child_name("list" if self.vault.accounts or self.vault.folders else "empty")

    def _build_group(self, title, accs, focus_id):
        group = Adw.PreferencesGroup(title=title)
        cols = self.settings["code_columns"]
        if cols == 1:
            targets = [group]
            per_col = len(accs)
        else:
            box = Gtk.Box(spacing=12, homogeneous=True)
            targets = [Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"],
                                   valign=Gtk.Align.START) for _ in range(cols)]
            for lb in targets:
                box.append(lb)
            group.add(box)
            per_col = math.ceil(len(accs) / cols)  # preenche coluna por coluna
        for i, a in enumerate(accs):
            row = AccountRow(self, a, compact=cols > 1)
            target = targets[i // per_col]
            target.add(row) if isinstance(target, Adw.PreferencesGroup) else target.append(row)
            self.rows.append(row)
            if a["id"] == focus_id:
                row.grab_focus()
        return group

    def _folder_tile(self, folder):
        n = sum(1 for a in self.vault.accounts if a.get("folder") == folder["id"])
        count = "vazia" if n == 0 else ("1 conta" if n == 1 else f"{n} contas")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.append(Gtk.Image(icon_name="folder-symbolic", pixel_size=28, margin_bottom=4))
        box.append(Gtk.Label(label=folder["name"], css_classes=["heading"],
                             ellipsize=Pango.EllipsizeMode.END, max_width_chars=18))
        box.append(Gtk.Label(label=count, css_classes=["dim-label", "caption"]))
        tile = Gtk.Button(child=box, css_classes=["card", "folder-tile"],
                          tooltip_text=f"Abrir a pasta {folder['name']}")
        tile.connect("clicked", lambda *_: self.open_folder(folder["id"]))

        # soltar uma conta no cartão move ela para a pasta
        target = Gtk.DropTarget.new(GObject.TYPE_STRING, Gdk.DragAction.MOVE)
        target.connect("enter", lambda *_: tile.add_css_class("drop-target") or Gdk.DragAction.MOVE)
        target.connect("leave", lambda *_: tile.remove_css_class("drop-target"))

        def drop(_t, value, _x, _y):
            tile.remove_css_class("drop-target")
            if not isinstance(value, str) or not value.startswith(DRAG_PREFIX):
                return False
            acc = self._account(value[len(DRAG_PREFIX):])
            if acc is None or acc.get("folder") == folder["id"]:
                return False
            self._set_account_folder(acc, folder["id"])
            return True

        target.connect("drop", drop)
        tile.add_controller(target)
        return tile

    def move_account(self, src_id, dst, after):
        """Move a conta src_id para antes/depois de dst, entrando na pasta de dst. Retorna se moveu."""
        src = self._account(src_id)
        if src is None or src is dst:
            return False
        if src.get("pinned", False) != dst.get("pinned", False):
            self.toast("Fixe ou desafixe a conta para movê-la para o outro grupo.")
            return False
        folder = dst.get("folder", "")
        changed = folder != src.get("folder", "")
        if folder:
            src["folder"] = folder
        else:
            src.pop("folder", None)
        self.vault.accounts.remove(src)
        self.vault.accounts.insert(self.vault.accounts.index(dst) + (1 if after else 0), src)
        self.vault.save()
        if changed:
            name = self.vault.folder_name(folder)
            self.toast(f"Movido para {name}" if name else "Removido da pasta")
        # adia a reconstrução para não destruir a linha dentro do próprio sinal
        GLib.idle_add(self.rebuild_list, src_id)
        return True

    def move_by(self, acc, delta):
        order = [r.acc for r in self.rows]  # ordem visível
        i = order.index(acc) + delta
        if (0 <= i < len(order) and order[i].get("pinned", False) == acc.get("pinned", False)
                and order[i].get("folder", "") == acc.get("folder", "")):
            self.move_account(acc["id"], order[i], delta > 0)

    # --- preferências

    def open_preferences(self, *_):
        dialog = Adw.PreferencesDialog(title="Preferências")
        page = Adw.PreferencesPage()

        home = Adw.PreferencesGroup(title="Tela inicial")
        show = Adw.SwitchRow(title="Mostrar códigos das pastas na tela inicial",
                             subtitle="Desligado: os códigos de uma pasta só aparecem ao entrar nela.",
                             active=self.settings["home_shows_folder_codes"])
        show.connect("notify::active", lambda r, _p: self._set_setting("home_shows_folder_codes", r.get_active()))
        home.add(show)
        page.add(home)

        layout = Adw.PreferencesGroup(title="Layout")
        per_row = Adw.SpinRow.new_with_range(*self.settings.LIMITS["folders_per_row"], 1)
        per_row.set_title("Pastas por linha")
        per_row.set_subtitle("Quantos cartões de pasta ficam lado a lado")
        per_row.set_value(self.settings["folders_per_row"])
        per_row.connect("notify::value", lambda r, _p: self._set_setting("folders_per_row", int(r.get_value())))
        cols = Adw.ComboRow(title="Colunas de códigos", subtitle="Com 2 colunas, alargue a janela",
                            model=Gtk.StringList.new(["1 coluna", "2 colunas"]))
        cols.set_selected(self.settings["code_columns"] - 1)
        cols.connect("notify::selected", lambda r, _p: self._set_setting("code_columns", r.get_selected() + 1))
        layout.add(per_row)
        layout.add(cols)
        page.add(layout)

        security = Adw.PreferencesGroup(title="Bloqueio automático")
        on_screen = Adw.SwitchRow(title="Bloquear quando a tela do computador bloquear",
                                  subtitle="Também bloqueia antes de suspender.",
                                  active=self.settings["lock_on_screen_lock"])
        on_screen.connect("notify::active",
                          lambda r, _p: self._set_setting("lock_on_screen_lock", r.get_active()))
        idle = Adw.SpinRow.new_with_range(*self.settings.LIMITS["auto_lock_minutes"], 1)
        idle.set_title("Bloquear após minutos sem foco")
        idle.set_subtitle("Janela em segundo plano ou minimizada. 0 = nunca.")
        idle.set_value(self.settings["auto_lock_minutes"])
        idle.connect("notify::value", lambda r, _p: self._set_setting("auto_lock_minutes", int(r.get_value())))
        security.add(on_screen)
        security.add(idle)
        page.add(security)

        dialog.add(page)
        dialog.present(self)

    def _set_setting(self, key, value):
        if self.settings[key] == value:
            return
        self.settings.set(key, value)
        if key == "code_columns" and value > 1 and self.get_width() < 900:
            self.set_default_size(980, self.get_height())  # dá espaço para as duas colunas
        if self.vault.unlocked and key in ("home_shows_folder_codes", "folders_per_row", "code_columns"):
            self.rebuild_list()

    def _tick(self):
        self._check_idle_lock()
        if self.vault.unlocked and self.rows:
            now = time.time()
            for r in self.rows:
                r.refresh(now)
        return GLib.SOURCE_CONTINUE

    def toast(self, msg, timeout=3):
        self.toasts.add_toast(Adw.Toast(title=msg, timeout=timeout))

    def copy_code(self, row):
        self.get_clipboard().set(row.current_code())
        self.toast(f"Código de {row.get_title()} copiado")

    def add_accounts(self, accounts):
        existing = {(a["secret"], a["issuer"], a["name"]) for a in self.vault.accounts}
        new = [a for a in accounts if (a["secret"], a["issuer"], a["name"]) not in existing]
        if not new:
            self.toast("Essa conta já está cadastrada.")
            return
        self.vault.accounts[:0] = new  # novas entram no topo
        self.vault.save()
        if self.current_folder is not None and any(a.get("folder", "") != self.current_folder for a in new):
            self.current_folder = None  # foi para outra pasta: mostra todas para não "sumir"
        self.rebuild_list()
        names = (new[0]["issuer"] or new[0]["name"]) if len(new) == 1 else f"{len(new)} contas"
        folder = self.vault.folder_name(new[0].get("folder")) if len({a.get("folder") for a in new}) == 1 else None
        self.toast(f"{names} adicionado ✓ em {folder}" if folder else f"{names} adicionado ✓")

    def set_pinned(self, acc, pinned):
        acc["pinned"] = pinned
        self.vault.save()
        # adia a reconstrução para não destruir o botão dentro do próprio sinal
        GLib.idle_add(self.rebuild_list)
        title = acc["issuer"] or acc["name"] or "Conta"
        self.toast(f"{title} fixado no topo" if pinned else f"{title} desafixado")

    # --- pastas

    def _account(self, acc_id):
        return next((a for a in self.vault.accounts if a["id"] == acc_id), None)

    @staticmethod
    def _menu_item(label, action, target):
        item = Gio.MenuItem.new(label.replace("_", "__"), None)  # "_" seria mnemônico
        item.set_action_and_target_value(action, target)
        return item

    def folder_menu_for(self, acc):
        current = acc.get("folder", "")
        options = Gio.Menu()
        if current:
            options.append_item(self._menu_item("Sem pasta", "win.move-to-folder",
                                                GLib.Variant("(ss)", (acc["id"], ""))))
        for f in self.vault.folders:
            if f["id"] != current:
                options.append_item(self._menu_item(f["name"], "win.move-to-folder",
                                                    GLib.Variant("(ss)", (acc["id"], f["id"]))))
        create = Gio.Menu()
        create.append_item(self._menu_item("Nova pasta…", "win.new-folder", GLib.Variant("s", acc["id"])))
        menu = Gio.Menu()
        menu.append_section(None, options)
        menu.append_section(None, create)
        return menu

    def extra_menu_for(self, acc):
        """Menu ⋮ da linha completa (fixar e pasta já têm botões próprios)."""
        options = Gio.Menu()
        options.append_item(self._menu_item("Exportar para outro app (QR code)…", "win.show-qr", GLib.Variant("s", acc["id"])))
        danger = Gio.Menu()
        danger.append_item(self._menu_item("Remover…", "win.delete-account", GLib.Variant("s", acc["id"])))
        menu = Gio.Menu()
        menu.append_section(None, options)
        menu.append_section(None, danger)
        return menu

    def row_menu_for(self, acc):
        pinned = acc.get("pinned", False)
        options = Gio.Menu()
        options.append_item(self._menu_item("Desafixar" if pinned else "Fixar no topo", "win.toggle-pin",
                                            GLib.Variant("s", acc["id"])))
        options.append_submenu("Mover para pasta", self.folder_menu_for(acc))
        options.append_item(self._menu_item("Exportar para outro app (QR code)…", "win.show-qr", GLib.Variant("s", acc["id"])))
        danger = Gio.Menu()
        danger.append_item(self._menu_item("Remover…", "win.delete-account", GLib.Variant("s", acc["id"])))
        menu = Gio.Menu()
        menu.append_section(None, options)
        menu.append_section(None, danger)
        return menu

    def on_toggle_pin(self, _action, param):
        acc = self._account(param.get_string())
        if acc is not None:
            self.set_pinned(acc, not acc.get("pinned", False))

    def on_delete_account(self, _action, param):
        acc = self._account(param.get_string())
        if acc is not None:
            self.confirm_delete(acc)

    # --- QR code, senha e backup

    def on_show_qr(self, _action, param):
        acc = self._account(param.get_string())
        if acc is None:
            return
        uri = build_otpauth(acc)
        title = acc["issuer"] or acc["name"] or "Conta"
        dialog = Adw.Dialog(title=f"Exportar {title}", content_width=400)
        toasts = Adw.ToastOverlay()
        view = Adw.ToolbarView()
        view.add_top_bar(Adw.HeaderBar())
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=6,
                      margin_bottom=18, margin_start=18, margin_end=18)
        box.append(Gtk.Label(label="No Microsoft ou Google Authenticator, toque em “+” e escaneie. "
                                   "Quem vir este QR code consegue gerar seus códigos.",
                             wrap=True, justify=Gtk.Justification.CENTER, css_classes=["dim-label"]))
        if (acc["algorithm"], acc["digits"], acc["period"]) != ("SHA1", 6, 30):
            box.append(Gtk.Label(
                label=f"Atenção: esta conta usa {acc['algorithm']}, {acc['digits']} dígitos e "
                      f"{acc['period']} s. O Microsoft Authenticator só aceita SHA1, 6 dígitos e 30 s, "
                      "e o Google pode gerar códigos errados.",
                wrap=True, justify=Gtk.Justification.CENTER, css_classes=["warning"]))
        texture = Gdk.Texture.new_from_bytes(GLib.Bytes.new(qr_png(uri)))
        picture = Gtk.Picture(paintable=texture, content_fit=Gtk.ContentFit.CONTAIN,
                              width_request=280, height_request=280, halign=Gtk.Align.CENTER,
                              css_classes=["qr-frame"])
        box.append(picture)

        # código atual, para conferir se o outro app gera o mesmo antes de remover daqui
        code_label = Gtk.Label(css_classes=["otp-code", "numeric"])
        box.append(Gtk.Label(label="Confira se o código no outro app é igual a este:",
                             css_classes=["caption", "dim-label"], wrap=True))
        box.append(code_label)

        def update_code():
            code_label.set_text(format_code(totp(acc)))
            return GLib.SOURCE_CONTINUE

        update_code()
        timer = GLib.timeout_add(1000, update_code)
        dialog.connect("closed", lambda *_: GLib.source_remove(timer))

        buttons = Gtk.Box(spacing=8, halign=Gtk.Align.CENTER)
        copy_link = Gtk.Button(label="Copiar link otpauth://", css_classes=["pill"])
        copy_link.connect("clicked", lambda *_: (
            self.get_clipboard().set(uri),
            toasts.add_toast(Adw.Toast(title="Link copiado. Ele contém a chave secreta.", timeout=3))))
        copy_key = Gtk.Button(label="Copiar chave", css_classes=["pill"],
                              tooltip_text="Para “digitar código manualmente” no outro app")
        copy_key.connect("clicked", lambda *_: (
            self.get_clipboard().set(acc["secret"]),
            toasts.add_toast(Adw.Toast(title="Chave secreta copiada.", timeout=3))))
        buttons.append(copy_link)
        buttons.append(copy_key)
        box.append(buttons)
        view.set_content(box)
        toasts.set_child(view)
        dialog.set_child(toasts)
        dialog.present(self)

    def _password_dialog(self, heading, body, fields, confirm, validate, on_ok):
        """AlertDialog com campos de senha. validate(textos) habilita o botão; on_ok(textos)."""
        dialog = Adw.AlertDialog(heading=heading, body=body)
        group = Adw.PreferencesGroup()
        rows = [Adw.PasswordEntryRow(title=f, activates_default=True) for f in fields]
        for r in rows:
            group.add(r)
        dialog.set_extra_child(group)
        dialog.add_response("cancel", "Cancelar")
        dialog.add_response("ok", confirm)
        dialog.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("ok")
        dialog.set_close_response("cancel")

        def update(*_):
            dialog.set_response_enabled("ok", validate([r.get_text() for r in rows]))

        for r in rows:
            r.connect("changed", update)
        update()

        def on_response(_d, response):
            if response == "ok" and self.vault.unlocked:
                on_ok([r.get_text() for r in rows])

        dialog.connect("response", on_response)
        dialog.present(self)
        dialog.set_focus(rows[0])

    def on_change_password(self, *_):
        if not self.vault.unlocked:
            return

        def change(texts):
            current, new, _confirm = texts
            if not self.vault.verify_password(current):
                self.toast("Senha atual incorreta. Nada foi alterado.", 4)
                return
            self.vault.change_password(new)
            if keyring_has_key():  # digital ativa: o chaveiro passa a guardar a chave nova
                try:
                    keyring_store_key(self.vault.key)
                except GLib.Error:
                    keyring_clear_key()
                    self.fp_action.set_state(GLib.Variant.new_boolean(False))
                    self.toast("Senha trocada, mas a digital foi desativada. Ative de novo no menu.", 5)
                    return
            self.toast("Senha mestra trocada ✓")

        self._password_dialog(
            "Trocar senha mestra",
            "Backups exportados antes da troca continuam abrindo com a senha antiga.",
            ("Senha atual", "Nova senha (mín. 6 caracteres)", "Confirmar nova senha"), "Trocar",
            lambda t: bool(t[0]) and len(t[1]) >= 6 and t[1] == t[2], change)

    def on_export_backup(self, *_):
        if not self.vault.unlocked:
            return
        self.vault.save()
        dialog = Gtk.FileDialog(title="Exportar backup",
                                initial_name=f"autenticador-backup-{time.strftime('%Y-%m-%d')}.json")
        docs = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOCUMENTS)
        if docs:
            dialog.set_initial_folder(Gio.File.new_for_path(docs))

        def done(d, res):
            try:
                file = d.save_finish(res)
                file.replace_contents(VAULT_PATH.read_bytes(), None, False,
                                      Gio.FileCreateFlags.PRIVATE | Gio.FileCreateFlags.REPLACE_DESTINATION,
                                      None)
            except GLib.Error as e:
                if e.domain != "gtk-dialog-error-quark":  # cancelou a escolha do arquivo: nada a fazer
                    self.toast(f"Não consegui salvar o backup: {e.message}", 5)
                return
            except OSError as e:
                self.toast(f"Não consegui salvar o backup: {e}", 5)
                return
            self.toast("Backup criptografado salvo. Ele abre com a senha mestra atual.", 5)

        dialog.save(self, None, done)

    def on_import_backup(self, *_):
        if not self.vault.unlocked:
            return
        filters = Gio.ListStore.new(Gtk.FileFilter)
        f = Gtk.FileFilter(name="Backup do Autenticador (.json)")
        f.add_pattern("*.json")
        filters.append(f)
        dialog = Gtk.FileDialog(title="Importar backup", filters=filters)

        def done(d, res):
            try:
                file = d.open_finish(res)
            except GLib.Error:
                return
            try:
                data = json.loads(file.load_contents(None)[1])
                salt, kdf = _b64d(data["salt"]), data["kdf"]
                _b64d(data["nonce"]), _b64d(data["ciphertext"])
                if not kdf["n"] <= 2 ** 20:  # evita travar com arquivo estranho
                    raise ValueError
            except (GLib.Error, ValueError, KeyError, TypeError):
                self.toast("Esse arquivo não é um backup do Autenticador.", 4)
                return
            if not self.vault.unlocked:
                return
            if salt == self.vault.salt and kdf == self.vault.kdf:  # mesma senha de hoje: abre direto
                try:
                    return self._restore(decrypt_vault(data, self.vault.key))
                except InvalidTag:
                    pass

            def with_password(texts):
                try:
                    content = decrypt_vault(data, derive_key(texts[0], data))
                except InvalidTag:
                    self.toast("Senha incorreta para esse backup.", 4)
                    return
                self._restore(content)

            self._password_dialog("Senha do backup",
                                  "Digite a senha mestra que estava em uso quando o backup foi feito.",
                                  ("Senha do backup",), "Importar", lambda t: bool(t[0]), with_password)

        dialog.open(self, None, done)

    def _restore(self, content):
        """Junta as contas e pastas do backup ao cofre, sem duplicar."""
        try:
            accounts = list(content["accounts"])
            folders = list(content.get("folders", []))
        except (KeyError, TypeError):
            self.toast("O backup está em um formato desconhecido.", 4)
            return
        if not content.get("ordered"):
            accounts.reverse()  # mesmo ajuste dos cofres antigos
        folder_ids = {}
        for f in folders:
            target = self.vault.find_folder(f["name"])
            if target is None:
                target = {"id": uuid.uuid4().hex, "name": f["name"]}
                self.vault.folders.append(target)
            folder_ids[f["id"]] = target["id"]
        existing = {(a["secret"], a["issuer"], a["name"]) for a in self.vault.accounts}
        added = skipped = 0
        for a in accounts:
            try:
                acc = make_account(a["secret"], a.get("issuer", ""), a.get("name", ""),
                                   a.get("algorithm", "SHA1"), a.get("digits", 6), a.get("period", 30))
            except (ParseError, KeyError):
                skipped += 1
                continue
            if (acc["secret"], acc["issuer"], acc["name"]) in existing:
                skipped += 1
                continue
            if a.get("pinned"):
                acc["pinned"] = True
            if folder_ids.get(a.get("folder")):
                acc["folder"] = folder_ids[a["folder"]]
            existing.add((acc["secret"], acc["issuer"], acc["name"]))
            self.vault.accounts.append(acc)
            added += 1
        self.vault.save()
        self.current_folder = None
        self.rebuild_list()
        msg = f"{added} conta(s) importada(s)" if added else "Nenhuma conta nova no backup"
        self.toast(msg + (f"; {skipped} já existia(m) ou eram inválidas" if skipped else ""), 5)

    def on_move_to_folder(self, _action, param):
        acc_id, fid = param.unpack()
        acc = self._account(acc_id)
        if acc is not None:
            self._set_account_folder(acc, fid)

    def _set_account_folder(self, acc, fid):
        if fid:
            acc["folder"] = fid
        else:
            acc.pop("folder", None)
        self.vault.save()
        title = acc["issuer"] or acc["name"] or "Conta"
        name = self.vault.folder_name(fid)
        self.toast(f"{title} movido para {name}" if name else f"{title} removido da pasta")
        # adia a reconstrução para não destruir o botão dentro do próprio sinal
        GLib.idle_add(self.rebuild_list, acc["id"])

    def on_new_folder(self, _action, param):
        """Cria pasta; com id de conta no parâmetro, já move a conta para ela."""
        acc = self._account(param.get_string())

        def create(name):
            folder = {"id": uuid.uuid4().hex, "name": name}
            self.vault.folders.append(folder)
            if acc is not None:
                self._set_account_folder(acc, folder["id"])  # salva e reconstrói
                return
            self.vault.save()
            self.open_folder(folder["id"])  # abre a pasta nova para adicionar contas nela
            self.toast(f"Pasta {name} criada. O + adiciona contas aqui.", 5)

        self._ask_folder_name("Nova pasta", "Criar", "", create)

    def _current_folder_obj(self):
        return next((f for f in self.vault.folders if f["id"] == self.current_folder), None)

    def on_rename_folder(self, *_):
        folder = self._current_folder_obj()
        if folder is None:
            return

        def rename(name):
            folder["name"] = name
            self.vault.save()
            self.rebuild_list()
            self.toast(f"Pasta renomeada para {name}")

        self._ask_folder_name("Renomear pasta", "Renomear", folder["name"], rename, exclude=folder)

    def on_delete_folder(self, *_):
        folder = self._current_folder_obj()
        if folder is None:
            return
        n = sum(1 for a in self.vault.accounts if a.get("folder") == folder["id"])
        dialog = Adw.AlertDialog(
            heading=f"Excluir a pasta {folder['name']}?",
            body=(f"As contas não são apagadas: {n} volta(m) para “Sem pasta”." if n
                  else "A pasta está vazia."))
        dialog.add_response("cancel", "Cancelar")
        dialog.add_response("delete", "Excluir pasta")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")

        def on_response(_d, response):
            if response != "delete":
                return
            for a in self.vault.accounts:
                if a.get("folder") == folder["id"]:
                    a.pop("folder", None)
            self.vault.folders.remove(folder)
            self.current_folder = None
            self.vault.save()
            self.rebuild_list()
            self.toast(f"Pasta {folder['name']} excluída")

        dialog.connect("response", on_response)
        dialog.present(self)

    def _ask_folder_name(self, heading, confirm, initial, on_done, exclude=None):
        dialog = Adw.AlertDialog(heading=heading)
        entry = Gtk.Entry(text=initial, placeholder_text="Nome da pasta", activates_default=True)
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancelar")
        dialog.add_response("ok", confirm)
        dialog.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("ok")
        dialog.set_close_response("cancel")

        def validate(*_):
            name = entry.get_text().strip()
            other = self.vault.find_folder(name)
            dialog.set_response_enabled("ok", bool(name) and (other is None or other is exclude))

        entry.connect("changed", validate)
        validate()
        dialog.connect("response", lambda _d, r: on_done(entry.get_text().strip()) if r == "ok" else None)
        dialog.present(self)
        dialog.set_focus(entry)
        entry.select_region(0, -1)

    def confirm_delete(self, acc):
        title = acc["issuer"] or acc["name"] or "esta conta"
        dialog = Adw.AlertDialog(
            heading=f"Remover {title}?",
            body="O código vai parar de ser gerado aqui. Antes, desative o 2FA no site "
                 "ou garanta que tem outro jeito de entrar (códigos de recuperação).")
        dialog.add_response("cancel", "Cancelar")
        dialog.add_response("delete", "Remover")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")

        def on_response(_d, response):
            if response == "delete":
                self.vault.accounts = [a for a in self.vault.accounts if a["id"] != acc["id"]]
                self.vault.save()
                self.rebuild_list()
                self.toast(f"{title} removido")

        dialog.connect("response", on_response)
        dialog.present(self)

    # --- adicionar

    def open_add_dialog(self):
        if self.vault.unlocked:
            AddDialog(self).present(self)

    def paste_direct(self):
        """Ctrl+V na janela principal: QR/link adiciona direto; outra coisa abre o diálogo."""
        if not self.vault.unlocked:
            return

        def on_texts(texts):
            try:
                accounts = []
                for t in texts:
                    parsed = parse_payload(t)
                    if parsed is None:
                        raise ParseError(t)
                    accounts.extend(parsed)
            except ParseError:
                dialog = AddDialog(self)
                dialog.present(self)
                dialog.handle_texts(texts)
                return
            for a in accounts:
                if self.current_folder:
                    a["folder"] = self.current_folder
            self.add_accounts(accounts)

        read_clipboard(self, on_texts, lambda msg: self.toast(msg, 4))

    def _shortcut_paste(self, *_):
        if self.get_visible_dialog() or not self.vault.unlocked or not self._on_codes():
            return False
        if isinstance(self.get_focus(), Gtk.Text):  # campo de busca
            return False
        self.paste_direct()
        return True

    def _shortcut_add(self, *_):
        if self.get_visible_dialog() or not self._on_codes():
            return False
        self.open_add_dialog()
        return True

    def _shortcut_lock(self, *_):
        self.lock()
        return True

    def _shortcut_back(self, *_):
        if self.get_visible_dialog() or self.current_folder is None or not self._on_codes():
            return False
        self.open_folder(None)
        return True

    def _shortcut_regenerate(self, *_):
        if self.get_visible_dialog() or self._on_codes():
            return False
        self.generator.generate_all()
        return True


class App(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def do_startup(self):
        Adw.Application.do_startup(self)
        provider = Gtk.CssProvider()
        provider.load_from_string(CSS)
        Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), provider,
                                                  Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    def do_activate(self):
        win = self.get_active_window() or Window(self)
        win.present()


if __name__ == "__main__":
    sys.exit(App().run(sys.argv))
