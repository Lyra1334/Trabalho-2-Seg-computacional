import hashlib
import secrets


def hash_sha3(data: bytes) -> bytes:
    # Usa SHA3-256 para o hash do rótulo e para gerar as máscaras.
    return hashlib.sha3_256(data).digest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    # Combina cada byte com o byte correspondente da máscara.
    return bytes(x ^ y for x, y in zip(a, b))


def mgf1(seed: bytes, length: int) -> bytes:
    # Gera blocos de hash até completar o tamanho pedido.
    result = b""
    for counter in range((length + 31) // 32):
        result += hash_sha3(seed + counter.to_bytes(4, "big"))
    return result[:length]


def oaep_encode(message: bytes, k: int = 256, label: bytes = b"") -> bytes:
    # OAEP reserva dois hashes e dois bytes para o bloco codificado.
    h_len = 32
    if k < 2 * h_len + 2 or len(message) > k - 2 * h_len - 2:
        raise ValueError("Mensagem é grande demais para OAEP")

    l_hash = hash_sha3(label)
    # DB contém o hash do rótulo, zeros, o separador e a mensagem.
    db = l_hash + b"\x00" * (k - len(message) - 2 * h_len - 2) + b"\x01" + message
    seed = secrets.token_bytes(h_len)
    # A seed e o DB são mascarados um com o outro.
    masked_db = xor_bytes(db, mgf1(seed, k - h_len - 1))
    masked_seed = xor_bytes(seed, mgf1(masked_db, h_len))
    return b"\x00" + masked_seed + masked_db


def oaep_decode(encoded: bytes, label: bytes = b"") -> bytes:
    # Desfaz as máscaras e verifica o hash do rótulo e o separador.
    h_len = 32
    if len(encoded) < 2 * h_len + 2 or encoded[0] != 0:
        raise ValueError("Codificação OAEP inválida")

    masked_seed = encoded[1 : h_len + 1]
    masked_db = encoded[h_len + 1 :]
    seed = xor_bytes(masked_seed, mgf1(masked_db, h_len))
    db = xor_bytes(masked_db, mgf1(seed, len(masked_db)))
    if db[:h_len] != hash_sha3(label):
        raise ValueError("Codificação OAEP inválida")

    padding = db[h_len:]
    separator = padding.find(b"\x01")
    if separator < 0 or any(padding[:separator]):
        raise ValueError("Codificação OAEP inválida")
    return padding[separator + 1 :]


def rsa_encrypt(message: bytes, public_key: tuple[int, int]) -> bytes:
    # A chave pública guarda n e e; RSA calcula mensagem^e mod n.
    n, e = public_key
    k = (n.bit_length() + 7) // 8
    if len(message) != k or int.from_bytes(message, "big") >= n:
        raise ValueError("Mensagem RSA inválida")
    value = pow(int.from_bytes(message, "big"), e, n)
    return value.to_bytes(k, "big")


def rsa_decrypt(ciphertext: bytes, private_key: tuple[int, int, int]) -> bytes:
    # A chave privada guarda p, q e d; n é o produto dos primos.
    p, q, d = private_key
    n = p * q
    k = (n.bit_length() + 7) // 8
    if len(ciphertext) != k or int.from_bytes(ciphertext, "big") >= n:
        raise ValueError("Texto cifrado RSA inválido")
    value = pow(int.from_bytes(ciphertext, "big"), d % ((p - 1) * (q - 1)), n)
    return value.to_bytes(k, "big")


def rsa_oaep_encrypt(
    message: bytes, public_key: tuple[int, int], label: bytes = b""
) -> bytes:
    # Ajusta o bloco OAEP ao tamanho da chave antes de cifrar.
    k = (public_key[0].bit_length() + 7) // 8
    return rsa_encrypt(oaep_encode(message, k, label), public_key)


def rsa_oaep_decrypt(
    ciphertext: bytes, private_key: tuple[int, int, int], label: bytes = b""
) -> bytes:
    # Primeiro decifra o bloco RSA, depois recupera a mensagem do OAEP.
    return oaep_decode(rsa_decrypt(ciphertext, private_key), label)
