"""CLI simples para gerar chaves, cifrar e decifrar mensagens com RSA."""

import argparse
from pathlib import Path

from RSAKeyGenerator import generateKeyPair
from RSACrypt import rsa_oaep_decrypt, rsa_oaep_encrypt


def key_size(value: str) -> int:
    try:
        bits = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Informe um número inteiro de bits.") from exc
    if bits < 16 or bits % 2:
        raise argparse.ArgumentTypeError(
            "O tamanho da chave deve ser um número par de pelo menos 16 bits."
        )
    return bits


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera chaves, cifra e decifra mensagens com RSA.")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--key-size",
        type=key_size,
        metavar="BITS",
        help="tamanho exato da chave pública em bits (número par)",
    )
    action.add_argument("--encrypt", nargs="?", const=True, metavar="TEXT", help="mensagem a cifrar em UTF-8")
    action.add_argument("--decrypt", nargs="?", const=True, metavar="HEX", help="mensagem cifrada em hexadecimal")
    parser.add_argument(
        "--output-prefix",
        default="rsa_key",
        metavar="PATH",
        help="prefixo dos arquivos _pub.txt e _priv.txt (padrão: rsa_key)",
    )
    parser.add_argument(
        "-i", "--input-file",
        metavar="PATH",
        help="arquivo de entrada para --encrypt ou --decrypt",
    )
    parser.add_argument(
        "-o", "--output-file",
        metavar="PATH",
        help="arquivo de saída para a mensagem cifrada ou decifrada",
    )
    args = parser.parse_args()

    if args.key_size is not None:
        if args.input_file is not None or args.output_file is not None:
            parser.error("-i e -o são usados apenas com --encrypt ou --decrypt")
        public_path = Path(f"{args.output_prefix}_pub.txt")
        while True:
            generateKeyPair(args.key_size // 2, args.output_prefix)
            modulus = int(public_path.read_text().splitlines()[0])
            if modulus.bit_length() == args.key_size:
                break

        print(f"Par de chaves RSA de {args.key_size} bits gerado:")
        print(f"  Chave pública: {public_path}")
        print(f"  Chave privada: {args.output_prefix}_priv.txt")
    elif args.encrypt is not None:
        if args.encrypt is True and args.input_file is None:
            parser.error("Informe a mensagem ou use -i para ler um arquivo")
        if args.encrypt is not True and args.input_file is not None:
            parser.error("Use a mensagem ou -i, não ambos")
        try:
            key = tuple(map(int, Path(f"{args.output_prefix}_pub.txt").read_text().split()))
            plaintext = Path(args.input_file).read_text(encoding="utf-8") if args.input_file else args.encrypt
            ciphertext = rsa_oaep_encrypt(plaintext.encode("utf-8"), key).hex()
            if args.output_file is not None:
                Path(args.output_file).write_text(ciphertext, encoding="utf-8")
            print(ciphertext)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    else:
        if args.decrypt is True and args.input_file is None:
            parser.error("Informe o texto cifrado ou use -i para ler um arquivo")
        if args.decrypt is not True and args.input_file is not None:
            parser.error("Use o texto cifrado ou -i, não ambos")
        try:
            key = tuple(map(int, Path(f"{args.output_prefix}_priv.txt").read_text().split()))
            ciphertext = Path(args.input_file).read_text(encoding="utf-8") if args.input_file else args.decrypt
            message = rsa_oaep_decrypt(bytes.fromhex(ciphertext), key)
            plaintext = message.decode("utf-8")
            if args.output_file is not None:
                Path(args.output_file).write_text(plaintext, encoding="utf-8")
            print(plaintext)
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            parser.error(str(exc))


if __name__ == "__main__":
    main()
