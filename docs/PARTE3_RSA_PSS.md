# Parte III — Assinatura digital RSA-PSS

Implementação de RSASSA-PSS (RFC 8017, seções 8.1 e 9.1) com SHA3-256 e MGF1-SHA3-256, em Python 3.10+.

## Arquivos

| Arquivo | Conteúdo |
|---|---|
| `pss.py` (raiz do repo) | MGF1, EMSA-PSS encode/verify, RSASP1/RSAVP1 (com CRT), assinatura/verificação de arquivos, formato `.sig`, CLI |
| `test_pss.py` | 23 testes: auxiliares, assinatura, adulterações, entradas inválidas e interoperabilidade |

## Como usar

```bash
# gerar chaves (Parte I): cria chave_pub.txt e chave_priv.txt
python RSAKeyGenerator.py

# assinar
python pss.py assinar documento.pdf --priv chave_priv.txt
# -> cria documento.pdf.sig e imprime a assinatura em Base64

# verificar
python pss.py verificar documento.pdf --pub chave_pub.txt
# código de saída: 0 = válida, 1 = inválida, 2 = erro de entrada

# testes (o bloco de interoperabilidade precisa de: pip install cryptography)
python -m unittest test_pss -v
```

Formato das chaves é o mesmo gravado por `generateKeyPair` da Parte I: `<prefixo>_pub.txt` com `n` e `e`, e `<prefixo>_priv.txt` com `p`, `q` e `d`, um número por linha. O carregador aceita `d` negativo, como o Euclides estendido original pode gerar, e também o formato `nome = valor`. Os testes usam `chave_pub.txt`/`chave_priv.txt` se existirem. Senão, geram um par com o `RSAKeyGenerator.py` da pasta.

## Formato do arquivo de assinatura (`.sig`)

```json
{
  "versao": 1,
  "algoritmo": "RSASSA-PSS",
  "hash": "SHA3-256",
  "mgf": "MGF1-SHA3-256",
  "salt_len": 32,
  "modulo_bits": 2048,
  "arquivo": "documento.pdf",
  "digest_sha3_256": "…hex…",
  "assinatura": "…Base64…"
}
```

O campo `digest_sha3_256` é só informativo: a verificação sempre recalcula o hash do arquivo e nunca confia nesse campo. Os parâmetros `algoritmo`, `hash`, `mgf` e `salt_len` são validados no parsing, e qualquer valor diferente é rejeitado (evita ataques de downgrade de algoritmo).

## Fluxo da assinatura

1. **Digest:** `mHash = SHA3-256(arquivo)`, lido em blocos de 64 KiB.
2. **Salt:** 32 bytes de `secrets.token_bytes` (CSPRNG).
3. **M′** = `0x00 × 8 ‖ mHash ‖ salt`, e **H** = `SHA3-256(M′)`.
4. **DB** = `PS (zeros) ‖ 0x01 ‖ salt`.
5. **maskedDB** = `DB ⊕ MGF1(H, emLen − hLen − 1)`. Os bits mais altos são zerados para garantir `EM < n`.
6. **EM** = `maskedDB ‖ H ‖ 0xBC`, com `emBits = modBits − 1`.
7. **Assinatura:** `s = EM^d mod n`, calculada via CRT e conferida com `s^e mod n == EM` para proteção contra falhas. A saída tem k bytes e é codificada em Base64.

A verificação faz o caminho inverso: `EM = s^e mod n`, confere `0xBC` e os bits zerados, desmascara o DB, confere `PS = 0…0 ‖ 0x01`, extrai o salt, recalcula `H′` e compara com `H` em tempo constante (`hmac.compare_digest`). Qualquer falha devolve apenas "inválida", sem dizer onde falhou, para não virar um oráculo.

## Por que isso não é "cifrar o hash"

Na abordagem ingênua, a assinatura seria `s = H(m)^d mod n`. Essa forma é determinística, maleável (a propriedade multiplicativa `s₁·s₂` assina `h₁·h₂`) e não tem prova de segurança. No PSS, o que é exponenciado é um bloco codificado de largura igual ao módulo, com três propriedades:

- Um **salt aleatório** torna a assinatura probabilística. O teste `test_probabilistico` mostra que duas assinaturas do mesmo arquivo saem diferentes e ambas são válidas.
- **H = Hash(0⁸ ‖ mHash ‖ salt)** amarra a mensagem ao salt.
- A **máscara MGF1** espalha H por todo o bloco e a estrutura fixa (`PS`, `0x01`, `0xBC`) é conferida na verificação.

O teste `test_nao_e_cifragem_do_hash` confirma que `s^e mod n` devolve o EM (terminado em `0xBC`), e não o digest. O esquema tem prova de segurança no modelo de oráculo aleatório (Bellare–Rogaway), com redução justa ao problema RSA.

## Decisões de implementação (para a arguição)

- **`sLen = hLen = 32`:** é o valor recomendado pela RFC 8017 e pela FIPS 186-5. Um salt maior não aumenta a segurança da prova.
- **`emBits = modBits − 1`:** garante que o inteiro EM seja sempre menor que n. Quando `modBits − 1` é múltiplo de 8, o `emLen` fica com um byte a menos que k, e o código trata esse caso.
- **CRT com checagem:** acelera a assinatura em cerca de 4× e protege contra o ataque de falha de Boneh–DeMillo–Lipton, em que uma única assinatura com erro em uma das metades vaza p ou q.
- **Aritmética própria:** a exponenciação usa square-and-multiply e o inverso modular usa Euclides estendido, sem `pow` embutido nem bibliotecas de RSA. Bibliotecas só entram para SHA3-256, Base64, CSPRNG e o teste de interoperabilidade (itens 1 e 3 das restrições).
- **`d` normalizado:** o Euclides estendido da Parte I pode devolver `d` negativo, então o carregamento faz `d mod φ(n)` e recupera `e = d⁻¹ mod φ(n)`.
- **Interoperabilidade:** a biblioteca `cryptography` (OpenSSL) verifica as nossas assinaturas, nós verificamos as dela, e ela rejeita as adulteradas.
