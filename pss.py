"""
CIC0201 - Segurança Computacional - Trabalho 2
Parte III - Assinatura digital RSA-PSS (RSASSA-PSS, RFC 8017 seção 8.1 e 9.1)

Tudo o que é "RSA" aqui é implementado à mão:
  - exponenciação modular (square-and-multiply) e inverso modular (Euclides estendido)
  - MGF1 (RFC 8017, B.2.1)
  - EMSA-PSS-ENCODE / EMSA-PSS-VERIFY (RFC 8017, 9.1.1 e 9.1.2)
  - RSASP1 / RSAVP1 (primitivas de assinatura/verificação, 5.2)
  - I2OSP / OS2IP (conversões inteiro <-> bytes, 4.1 e 4.2)

Bibliotecas usadas só para operações auxiliares (permitido pelo enunciado):
  - hashlib.sha3_256  -> função hash SHA3-256
  - secrets           -> geração do salt (CSPRNG)
  - base64, json, hmac.compare_digest -> codificação e comparação em tempo constante

Parâmetros adotados:
  Hash = SHA3-256 (hLen = 32 bytes), MGF = MGF1 com SHA3-256, sLen = 32 bytes.

Uso pela linha de comando:
  python pss.py assinar   <arquivo> --priv chave_privada.txt [--saida arquivo.sig]
  python pss.py verificar <arquivo> --pub  chave_publica.txt [--sig arquivo.sig]
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Parâmetros do esquema
# ---------------------------------------------------------------------------
HASH_NOME = "SHA3-256"
H_LEN = 32          # tamanho da saída do SHA3-256 em bytes
S_LEN = 32          # tamanho do salt (recomendação usual: sLen = hLen)
TRAILER = 0xBC      # byte final fixo do EM (RFC 8017)
VERSAO_FORMATO = 1


class ErroAssinatura(Exception):
    """Erro genérico de assinatura/verificação. A mensagem é propositalmente
    pouco específica na verificação, para não vazar informação."""


# ---------------------------------------------------------------------------
# Aritmética modular (implementação própria)
# ---------------------------------------------------------------------------
def exp_mod(base: int, expoente: int, modulo: int) -> int:
    """Exponenciação modular por square-and-multiply (esquerda para direita)."""
    if modulo <= 0:
        raise ValueError("módulo deve ser positivo")
    if expoente < 0:
        raise ValueError("expoente negativo não suportado")
    resultado = 1
    base %= modulo
    for bit in bin(expoente)[2:]:
        resultado = (resultado * resultado) % modulo
        if bit == "1":
            resultado = (resultado * base) % modulo
    return resultado


def inverso_modular(a: int, m: int) -> int:
    """Inverso de a módulo m via algoritmo de Euclides estendido (iterativo)."""
    r0, r1 = a % m, m
    s0, s1 = 1, 0
    while r1 != 0:
        quociente = r0 // r1
        r0, r1 = r1, r0 - quociente * r1
        s0, s1 = s1, s0 - quociente * s1
    if r0 != 1:
        raise ValueError("inverso modular não existe (mdc != 1)")
    return s0 % m  # normaliza para [0, m)


# ---------------------------------------------------------------------------
# Conversões (RFC 8017, seção 4)
# ---------------------------------------------------------------------------
def i2osp(x: int, tamanho: int) -> bytes:
    """Integer-to-Octet-String: inteiro -> bytes big-endian de tamanho fixo."""
    if x < 0 or x >= 256 ** tamanho:
        raise ValueError("inteiro grande demais")
    return x.to_bytes(tamanho, "big")


def os2ip(octetos: bytes) -> int:
    """Octet-String-to-Integer: bytes big-endian -> inteiro."""
    return int.from_bytes(octetos, "big")


# ---------------------------------------------------------------------------
# Hash e MGF1
# ---------------------------------------------------------------------------
def sha3_256(dados: bytes) -> bytes:
    return hashlib.sha3_256(dados).digest()


def digest_arquivo(caminho: str, bloco: int = 64 * 1024) -> bytes:
    """SHA3-256 do arquivo inteiro, lido em blocos (funciona para arquivos grandes)."""
    h = hashlib.sha3_256()
    with open(caminho, "rb") as f:
        while True:
            pedaco = f.read(bloco)
            if not pedaco:
                break
            h.update(pedaco)
    return h.digest()


def mgf1(semente: bytes, tamanho_mascara: int) -> bytes:
    """MGF1 (RFC 8017, B.2.1) com SHA3-256:
    T = Hash(semente || C0) || Hash(semente || C1) || ...  truncado em tamanho_mascara."""
    if tamanho_mascara > (2 ** 32) * H_LEN:
        raise ValueError("máscara longa demais")
    t = bytearray()
    contador = 0
    while len(t) < tamanho_mascara:
        t += sha3_256(semente + i2osp(contador, 4))
        contador += 1
    return bytes(t[:tamanho_mascara])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# EMSA-PSS (RFC 8017, 9.1)
# ---------------------------------------------------------------------------
def emsa_pss_encode(m_hash: bytes, em_bits: int, salt: bytes | None = None) -> bytes:
    """Codificação PSS. Recebe o digest mHash = SHA3-256(M) já calculado.

    M'    = 0x00*8 || mHash || salt
    H     = Hash(M')
    DB    = PS (zeros) || 0x01 || salt
    maskedDB = DB xor MGF1(H, emLen - hLen - 1)
    EM    = maskedDB || H || 0xBC
    """
    if len(m_hash) != H_LEN:
        raise ValueError("mHash com tamanho incorreto")
    em_len = (em_bits + 7) // 8
    if em_len < H_LEN + S_LEN + 2:
        raise ErroAssinatura("erro de codificação: módulo pequeno demais")

    if salt is None:
        salt = secrets.token_bytes(S_LEN)   # salt aleatório -> assinatura probabilística
    if len(salt) != S_LEN:
        raise ValueError("salt com tamanho incorreto")

    m_linha = b"\x00" * 8 + m_hash + salt
    h = sha3_256(m_linha)

    ps = b"\x00" * (em_len - S_LEN - H_LEN - 2)
    db = ps + b"\x01" + salt
    db_mask = mgf1(h, em_len - H_LEN - 1)
    masked_db = bytearray(xor_bytes(db, db_mask))

    # Zera os (8*emLen - emBits) bits mais à esquerda, garantindo EM < 2^emBits < n
    bits_zerar = 8 * em_len - em_bits
    masked_db[0] &= 0xFF >> bits_zerar

    return bytes(masked_db) + h + bytes([TRAILER])


def emsa_pss_verify(m_hash: bytes, em: bytes, em_bits: int) -> bool:
    """Verificação da codificação PSS. Retorna True/False (nunca lança por formato)."""
    em_len = (em_bits + 7) // 8
    if len(m_hash) != H_LEN or len(em) != em_len:
        return False
    if em_len < H_LEN + S_LEN + 2:
        return False
    if em[-1] != TRAILER:
        return False

    masked_db = em[: em_len - H_LEN - 1]
    h = em[em_len - H_LEN - 1 : -1]

    bits_zerar = 8 * em_len - em_bits
    if masked_db[0] & (0xFF << (8 - bits_zerar)) & 0xFF:
        return False

    db = bytearray(xor_bytes(masked_db, mgf1(h, em_len - H_LEN - 1)))
    db[0] &= 0xFF >> bits_zerar

    tam_ps = em_len - H_LEN - S_LEN - 2
    if any(db[:tam_ps]) or db[tam_ps] != 0x01:
        return False

    salt = bytes(db[-S_LEN:])
    h_linha = sha3_256(b"\x00" * 8 + m_hash + salt)
    return hmac.compare_digest(h, h_linha)


# ---------------------------------------------------------------------------
# Chaves
# ---------------------------------------------------------------------------
@dataclass
class ChavePublica:
    n: int
    e: int

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def k(self) -> int:  # tamanho do módulo em bytes
        return (self.bits + 7) // 8


@dataclass
class ChavePrivada:
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def k(self) -> int:
        return (self.bits + 7) // 8

    @classmethod
    def de_primos(cls, p: int, q: int, d: int) -> "ChavePrivada":
        """Monta a chave a partir de (p, q, d), formato que a Parte I grava.
        Normaliza d para [0, phi) (o Euclides estendido pode devolver d negativo)
        e recupera e = d^-1 mod phi."""
        if p == q:
            raise ValueError("p e q devem ser distintos")
        phi = (p - 1) * (q - 1)
        d %= phi
        e = inverso_modular(d, phi)
        return cls(n=p * q, e=e, d=d, p=p, q=q)

    def publica(self) -> ChavePublica:
        return ChavePublica(self.n, self.e)


def _ler_inteiros(caminho: str) -> tuple[dict[str, int], list[int]]:
    """Lê um arquivo de chave. Aceita 'nome = valor' / 'nome: valor' ou só números."""
    with open(caminho, "r", encoding="utf-8") as f:
        texto = f.read()
    nomeados = {k.lower(): int(v) for k, v in re.findall(r"\b([a-zA-Z]+)\s*[=:]\s*(-?\d+)", texto)}
    soltos = [int(x) for x in re.findall(r"-?\d+", texto)]  # d pode ser negativo
    return nomeados, soltos


def carregar_chave_publica(caminho: str) -> ChavePublica:
    nomeados, soltos = _ler_inteiros(caminho)
    if "n" in nomeados and "e" in nomeados:
        return ChavePublica(nomeados["n"], nomeados["e"])
    if len(soltos) == 2:
        return ChavePublica(*soltos)  # ordem (n, e), como na Parte I
    raise ValueError(f"formato de chave pública não reconhecido: {caminho}")


def carregar_chave_privada(caminho: str) -> ChavePrivada:
    nomeados, soltos = _ler_inteiros(caminho)
    if all(x in nomeados for x in ("p", "q", "d")):
        return ChavePrivada.de_primos(nomeados["p"], nomeados["q"], nomeados["d"])
    if len(soltos) == 3:
        return ChavePrivada.de_primos(*soltos)  # ordem (p, q, d), como na Parte I
    raise ValueError(f"formato de chave privada não reconhecido: {caminho}")


# ---------------------------------------------------------------------------
# Primitivas RSA (RFC 8017, 5.2)
# ---------------------------------------------------------------------------
def rsasp1(chave: ChavePrivada, m: int) -> int:
    """s = m^d mod n, usando CRT (Garner) para acelerar ~4x.
    Ao final confere s^e mod n == m, o que protege contra falhas no cálculo
    via CRT (ataque de Bellcore/Boneh-DeMillo-Lipton)."""
    if not 0 <= m < chave.n:
        raise ErroAssinatura("representante da mensagem fora do intervalo")
    dp = chave.d % (chave.p - 1)
    dq = chave.d % (chave.q - 1)
    q_inv = inverso_modular(chave.q, chave.p)
    s1 = exp_mod(m, dp, chave.p)
    s2 = exp_mod(m, dq, chave.q)
    h = (q_inv * (s1 - s2)) % chave.p
    s = s2 + chave.q * h
    if exp_mod(s, chave.e, chave.n) != m:
        raise ErroAssinatura("falha interna no cálculo da assinatura")
    return s


def rsavp1(chave: ChavePublica, s: int) -> int:
    """m = s^e mod n."""
    if not 0 <= s < chave.n:
        raise ErroAssinatura("representante da assinatura fora do intervalo")
    return exp_mod(s, chave.e, chave.n)


# ---------------------------------------------------------------------------
# RSASSA-PSS (RFC 8017, 8.1)
# ---------------------------------------------------------------------------
def assinar_digest(chave: ChavePrivada, m_hash: bytes, salt: bytes | None = None) -> bytes:
    """RSASSA-PSS-SIGN a partir do digest. Devolve a assinatura com k bytes."""
    em_bits = chave.bits - 1
    em = emsa_pss_encode(m_hash, em_bits, salt)
    m = os2ip(em)
    s = rsasp1(chave, m)
    return i2osp(s, chave.k)


def verificar_digest(chave: ChavePublica, m_hash: bytes, assinatura: bytes) -> bool:
    """RSASSA-PSS-VERIFY a partir do digest. Nunca lança exceção: devolve bool."""
    try:
        if len(assinatura) != chave.k:
            return False
        s = os2ip(assinatura)
        m = rsavp1(chave, s)
        em_bits = chave.bits - 1
        em_len = (em_bits + 7) // 8
        em = i2osp(m, em_len)  # falha se m >= 256^emLen -> assinatura inválida
        return emsa_pss_verify(m_hash, em, em_bits)
    except (ErroAssinatura, ValueError):
        return False


def assinar_bytes(chave: ChavePrivada, mensagem: bytes) -> bytes:
    return assinar_digest(chave, sha3_256(mensagem))


def verificar_bytes(chave: ChavePublica, mensagem: bytes, assinatura: bytes) -> bool:
    return verificar_digest(chave, sha3_256(mensagem), assinatura)


# ---------------------------------------------------------------------------
# Formato do arquivo de assinatura (.sig, JSON) -- usado pela Parte IV
# ---------------------------------------------------------------------------
def assinar_arquivo(caminho: str, chave: ChavePrivada) -> dict:
    m_hash = digest_arquivo(caminho)
    assinatura = assinar_digest(chave, m_hash)
    return {
        "versao": VERSAO_FORMATO,
        "algoritmo": "RSASSA-PSS",
        "hash": HASH_NOME,
        "mgf": "MGF1-" + HASH_NOME,
        "salt_len": S_LEN,
        "modulo_bits": chave.bits,
        "arquivo": os.path.basename(caminho),
        # só informativo: a verificação SEMPRE recalcula o digest do arquivo
        "digest_sha3_256": m_hash.hex(),
        "assinatura": base64.b64encode(assinatura).decode("ascii"),
    }


def ler_estrutura_assinada(caminho_sig: str) -> dict:
    """Parsing do .sig com validação dos campos (entrada tratada como não confiável)."""
    try:
        with open(caminho_sig, "r", encoding="utf-8") as f:
            dados = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ErroAssinatura(f"arquivo de assinatura ilegível: {exc}") from None
    if not isinstance(dados, dict):
        raise ErroAssinatura("estrutura de assinatura inválida")
    esperado = {"algoritmo": "RSASSA-PSS", "hash": HASH_NOME,
                "mgf": "MGF1-" + HASH_NOME, "salt_len": S_LEN}
    for campo, valor in esperado.items():
        if dados.get(campo) != valor:
            raise ErroAssinatura(f"parâmetro não suportado: {campo}={dados.get(campo)!r}")
    if not isinstance(dados.get("assinatura"), str):
        raise ErroAssinatura("campo 'assinatura' ausente")
    try:
        dados["assinatura_bytes"] = base64.b64decode(dados["assinatura"], validate=True)
    except (binascii.Error, ValueError):
        raise ErroAssinatura("assinatura não é Base64 válido") from None
    return dados


def verificar_arquivo(caminho: str, caminho_sig: str, chave: ChavePublica) -> bool:
    estrutura = ler_estrutura_assinada(caminho_sig)
    return verificar_digest(chave, digest_arquivo(caminho), estrutura["assinatura_bytes"])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Assinatura RSA-PSS (SHA3-256) - CIC0201 Trab. 2")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("assinar", help="assina um arquivo")
    a.add_argument("arquivo")
    a.add_argument("--priv", required=True, help="arquivo da chave privada (p, q, d)")
    a.add_argument("--saida", help="arquivo .sig de saída (padrão: <arquivo>.sig)")

    v = sub.add_parser("verificar", help="verifica a assinatura de um arquivo")
    v.add_argument("arquivo")
    v.add_argument("--pub", required=True, help="arquivo da chave pública (n, e)")
    v.add_argument("--sig", help="arquivo .sig (padrão: <arquivo>.sig)")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "assinar":
            chave = carregar_chave_privada(args.priv)
            estrutura = assinar_arquivo(args.arquivo, chave)
            saida = args.saida or args.arquivo + ".sig"
            with open(saida, "w", encoding="utf-8") as f:
                json.dump(estrutura, f, indent=2, ensure_ascii=False)
            print(f"Arquivo assinado ({chave.bits} bits). Assinatura salva em {saida}")
            print("Assinatura (Base64):")
            print(estrutura["assinatura"])
            return 0

        chave = carregar_chave_publica(args.pub)
        ok = verificar_arquivo(args.arquivo, args.sig or args.arquivo + ".sig", chave)
        print("ASSINATURA VÁLIDA: arquivo íntegro e autêntico." if ok
              else "ASSINATURA INVÁLIDA: arquivo adulterado, assinatura corrompida ou chave errada.")
        return 0 if ok else 1
    except (OSError, ValueError, ErroAssinatura) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
