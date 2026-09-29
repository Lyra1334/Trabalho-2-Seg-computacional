"""
Testes da Parte III (RSA-PSS). Rodar com:  python -m unittest test_pss -v

Origem das chaves de teste (na ordem):
  1. chave_priv.txt / chave_pub.txt na pasta (geradas pela Parte I com
     generateKeyPair(1024, "chave"));
  2. RSAKeyGenerator.py na pasta -> gera um par na hora (uma vez só);
  3. biblioteca `cryptography`, apenas como último recurso para teste
     (permitido pelo item 3 das restrições).
"""

import base64
import json
import os
import tempfile
import unittest

import pss

AQUI = os.path.dirname(os.path.abspath(__file__))
PREFIXO = os.path.join(AQUI, "chave")
PRIV_PARTE1 = PREFIXO + "_priv.txt"
PUB_PARTE1 = PREFIXO + "_pub.txt"

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    TEM_CRYPTOGRAPHY = True
except ImportError:
    TEM_CRYPTOGRAPHY = False


_CACHE = {}


def obter_chaves():
    if "chaves" in _CACHE:
        return _CACHE["chaves"]
    if not (os.path.exists(PRIV_PARTE1) and os.path.exists(PUB_PARTE1)):
        try:
            import RSAKeyGenerator  # Parte I do grupo
            RSAKeyGenerator.generateKeyPair(1024, PREFIXO)
        except ImportError:
            pass
    if os.path.exists(PRIV_PARTE1) and os.path.exists(PUB_PARTE1):
        chaves = (pss.carregar_chave_privada(PRIV_PARTE1), pss.carregar_chave_publica(PUB_PARTE1))
    elif TEM_CRYPTOGRAPHY:
        nums = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_numbers()
        priv = pss.ChavePrivada.de_primos(nums.p, nums.q, nums.d)
        chaves = (priv, priv.publica())
    else:
        raise unittest.SkipTest("sem chaves da Parte I e sem 'cryptography'")
    _CACHE["chaves"] = chaves
    return chaves


class TestAuxiliares(unittest.TestCase):
    def test_exp_mod(self):
        for b, e, m in [(4, 13, 497), (2, 1000, 10**9 + 7), (123456789, 987654321, 2**127 - 1)]:
            self.assertEqual(pss.exp_mod(b, e, m), pow(b, e, m))

    def test_inverso_modular(self):
        self.assertEqual(pss.inverso_modular(17, 3120), 2753)
        with self.assertRaises(ValueError):
            pss.inverso_modular(6, 9)

    def test_d_negativo_normalizado(self):
        # p=61, q=53, phi=3120, e=17 -> d=2753; Euclides pode devolver 2753-3120 = -367
        k = pss.ChavePrivada.de_primos(61, 53, -367)
        self.assertEqual(k.d, 2753)
        self.assertEqual(k.e, 17)

    def test_arquivo_parte1_com_d_negativo(self):
        with tempfile.TemporaryDirectory() as tmp:
            priv_path = os.path.join(tmp, "k_priv.txt")
            with open(priv_path, "w") as f:
                f.write("61\n53\n-367")  # exatamente o formato de generateKeyPair
            k = pss.carregar_chave_privada(priv_path)
            self.assertEqual((k.d, k.e, k.n), (2753, 17, 3233))

    def test_chave_bate_com_publica(self):
        priv, pub = obter_chaves()
        self.assertEqual((priv.n, priv.e), (pub.n, pub.e))

    def test_mgf1_tamanho_e_determinismo(self):
        a = pss.mgf1(b"semente", 100)
        self.assertEqual(len(a), 100)
        self.assertEqual(a, pss.mgf1(b"semente", 100))
        self.assertEqual(a[:32], pss.sha3_256(b"semente" + b"\x00\x00\x00\x00"))

    def test_i2osp_os2ip(self):
        self.assertEqual(pss.os2ip(pss.i2osp(65537, 4)), 65537)
        with self.assertRaises(ValueError):
            pss.i2osp(256, 1)


class TestPSS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv, cls.pub = obter_chaves()
        cls.tmp = tempfile.mkdtemp()
        cls.arquivo = os.path.join(cls.tmp, "documento.txt")
        with open(cls.arquivo, "wb") as f:
            f.write(b"Contrato de teste - CIC0201 - Trabalho 2\n" * 50)

    def assinar_para_arquivo(self):
        estrutura = pss.assinar_arquivo(self.arquivo, self.priv)
        sig_path = self.arquivo + ".sig"
        with open(sig_path, "w", encoding="utf-8") as f:
            json.dump(estrutura, f)
        return estrutura, sig_path

    def test_modulo_minimo(self):
        self.assertGreaterEqual(self.priv.bits, 2048,
                                "módulo abaixo de 2048 bits: problema na geração de primos (Parte I)")

    def test_assina_e_verifica(self):
        _, sig_path = self.assinar_para_arquivo()
        self.assertTrue(pss.verificar_arquivo(self.arquivo, sig_path, self.pub))

    def test_saida_em_base64(self):
        estrutura, _ = self.assinar_para_arquivo()
        bruto = base64.b64decode(estrutura["assinatura"], validate=True)
        self.assertEqual(len(bruto), self.priv.k)

    def test_probabilistico(self):
        """Mesmo arquivo, mesma chave -> assinaturas diferentes (salt), ambas válidas."""
        s1 = pss.assinar_bytes(self.priv, b"mensagem")
        s2 = pss.assinar_bytes(self.priv, b"mensagem")
        self.assertNotEqual(s1, s2)
        self.assertTrue(pss.verificar_bytes(self.pub, b"mensagem", s1))
        self.assertTrue(pss.verificar_bytes(self.pub, b"mensagem", s2))

    def test_nao_e_cifragem_do_hash(self):
        """s^e mod n NÃO é o hash: é o EM codificado (termina em 0xBC, tem máscara)."""
        m_hash = pss.sha3_256(b"x")
        s = pss.os2ip(pss.assinar_digest(self.priv, m_hash))
        em = pss.i2osp(pss.rsavp1(self.pub, s), (self.pub.bits - 1 + 7) // 8)
        self.assertEqual(em[-1], 0xBC)
        self.assertNotIn(m_hash, em)

    # --- adulterações (também usadas na Parte IV) ---
    def test_adultera_byte_do_arquivo(self):
        _, sig_path = self.assinar_para_arquivo()
        alterado = os.path.join(self.tmp, "alterado.txt")
        with open(self.arquivo, "rb") as f:
            dados = bytearray(f.read())
        dados[10] ^= 0x01
        with open(alterado, "wb") as f:
            f.write(dados)
        self.assertFalse(pss.verificar_arquivo(alterado, sig_path, self.pub))

    def test_adultera_byte_da_assinatura(self):
        estrutura, sig_path = self.assinar_para_arquivo()
        bruto = bytearray(base64.b64decode(estrutura["assinatura"]))
        bruto[len(bruto) // 2] ^= 0x01
        estrutura["assinatura"] = base64.b64encode(bruto).decode()
        with open(sig_path, "w", encoding="utf-8") as f:
            json.dump(estrutura, f)
        self.assertFalse(pss.verificar_arquivo(self.arquivo, sig_path, self.pub))

    def test_adultera_chave_publica(self):
        _, sig_path = self.assinar_para_arquivo()
        outra_e = pss.ChavePublica(self.pub.n, self.pub.e + 2)
        outro_n = pss.ChavePublica(self.pub.n ^ (1 << 100), self.pub.e)
        self.assertFalse(pss.verificar_arquivo(self.arquivo, sig_path, outra_e))
        self.assertFalse(pss.verificar_arquivo(self.arquivo, sig_path, outro_n))

    # --- entradas inválidas ---
    def test_assinatura_tamanho_errado(self):
        self.assertFalse(pss.verificar_bytes(self.pub, b"m", b"\x01" * 10))

    def test_assinatura_maior_que_n(self):
        self.assertFalse(pss.verificar_bytes(self.pub, b"m", b"\xff" * self.pub.k))

    def test_base64_invalido(self):
        estrutura, sig_path = self.assinar_para_arquivo()
        estrutura["assinatura"] = "isso não é base64!!"
        with open(sig_path, "w", encoding="utf-8") as f:
            json.dump(estrutura, f)
        with self.assertRaises(pss.ErroAssinatura):
            pss.verificar_arquivo(self.arquivo, sig_path, self.pub)

    def test_parametro_nao_suportado(self):
        estrutura, sig_path = self.assinar_para_arquivo()
        estrutura["hash"] = "MD5"
        with open(sig_path, "w", encoding="utf-8") as f:
            json.dump(estrutura, f)
        with self.assertRaises(pss.ErroAssinatura):
            pss.verificar_arquivo(self.arquivo, sig_path, self.pub)

    def test_sig_corrompido(self):
        sig_path = os.path.join(self.tmp, "lixo.sig")
        with open(sig_path, "wb") as f:
            f.write(b"\x00\xff{{{")
        with self.assertRaises(pss.ErroAssinatura):
            pss.verificar_arquivo(self.arquivo, sig_path, self.pub)


@unittest.skipUnless(TEM_CRYPTOGRAPHY, "biblioteca 'cryptography' não instalada")
class TestInteroperabilidade(unittest.TestCase):
    """Teste adicional: compara nossa implementação com uma biblioteca consolidada."""

    @classmethod
    def setUpClass(cls):
        cls.priv, cls.pub = obter_chaves()
        n, e = cls.pub.n, cls.pub.e
        cls.lib_pub = rsa.RSAPublicNumbers(e, n).public_key()
        p, q, d = cls.priv.p, cls.priv.q, cls.priv.d
        cls.lib_priv = rsa.RSAPrivateNumbers(
            p, q, d, d % (p - 1), d % (q - 1), rsa.rsa_crt_iqmp(p, q),
            rsa.RSAPublicNumbers(e, n)).private_key()
        cls.padding = padding.PSS(mgf=padding.MGF1(hashes.SHA3_256()), salt_length=32)

    def test_biblioteca_verifica_nossa_assinatura(self):
        msg = b"interoperabilidade"
        sig = pss.assinar_bytes(self.priv, msg)
        self.lib_pub.verify(sig, msg, self.padding, hashes.SHA3_256())  # lança se inválida

    def test_nos_verificamos_assinatura_da_biblioteca(self):
        msg = b"interoperabilidade"
        sig = self.lib_priv.sign(msg, self.padding, hashes.SHA3_256())
        self.assertTrue(pss.verificar_bytes(self.pub, msg, sig))

    def test_biblioteca_rejeita_assinatura_adulterada(self):
        sig = bytearray(pss.assinar_bytes(self.priv, b"x"))
        sig[5] ^= 1
        with self.assertRaises(InvalidSignature):
            self.lib_pub.verify(bytes(sig), b"x", self.padding, hashes.SHA3_256())


if __name__ == "__main__":
    unittest.main(verbosity=2)
