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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gera chaves, cifra e decifra mensagens com RSA."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    keygen_parser = commands.add_parser("keygen", help="gera um par de chaves RSA")
    keygen_parser.add_argument(
        "--key-size",
        type=key_size,
        required=True,
        metavar="BITS",
        help="tamanho exato da chave pública em bits (número par)",
    )

    encrypt_parser = commands.add_parser("encrypt", help="cifra uma mensagem em UTF-8")
    encrypt_parser.add_argument(
        "message", nargs="?", metavar="TEXT", help="mensagem a cifrar em UTF-8"
    )

    decrypt_parser = commands.add_parser(
        "decrypt", help="decifra uma mensagem em hexadecimal"
    )
    decrypt_parser.add_argument(
        "ciphertext", nargs="?", metavar="HEX", help="mensagem cifrada em hexadecimal"
    )

    keygen_parser.add_argument(
        "--output-prefix",
        default="rsa_key",
        metavar="PATH",
        help="prefixo dos arquivos _pub.txt e _priv.txt (padrão: rsa_key)",
    )

    for command_parser in (encrypt_parser, decrypt_parser):
        command_parser.add_argument(
            "-k",
            dest="key_file",
            required=True,
            metavar="PATH",
            help="arquivo com a chave RSA",
        )
        command_parser.add_argument(
            "-i", "--input-file", metavar="PATH", help="arquivo de entrada da mensagem"
        )
        command_parser.add_argument(
            "-o", "--output-file", metavar="PATH", help="arquivo de saída da mensagem"
        )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "keygen":
        public_path = Path(f"{args.output_prefix}_pub.txt")
        while True:
            generateKeyPair(args.key_size // 2, args.output_prefix)
            modulus = int(public_path.read_text().splitlines()[0])
            if modulus.bit_length() == args.key_size:
                break

        print(f"Par de chaves RSA de {args.key_size} bits gerado:")
        print(f"  Chave pública: {public_path}")
        print(f"  Chave privada: {args.output_prefix}_priv.txt")
    elif args.command == "encrypt":
        if args.message is None and args.input_file is None:
            parser.error("Informe a mensagem ou use -i para ler um arquivo")
        if args.message is not None and args.input_file is not None:
            parser.error("Use a mensagem ou -i, não ambos")
        try:
            key = tuple(map(int, Path(args.key_file).read_text().split()))
            plaintext = (
                Path(args.input_file).read_text(encoding="utf-8")
                if args.input_file
                else args.message
            )
            ciphertext = rsa_oaep_encrypt(plaintext.encode("utf-8"), key).hex()
            if args.output_file is not None:
                Path(args.output_file).write_text(ciphertext, encoding="utf-8")
            print(ciphertext)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    elif args.command == "decrypt":
        if args.ciphertext is None and args.input_file is None:
            parser.error("Informe o texto cifrado ou use -i para ler um arquivo")
        if args.ciphertext is not None and args.input_file is not None:
            parser.error("Use o texto cifrado ou -i, não ambos")
        try:
            key = tuple(map(int, Path(args.key_file).read_text().split()))
            ciphertext = (
                Path(args.input_file).read_text(encoding="utf-8")
                if args.input_file
                else args.ciphertext
            )
            message = rsa_oaep_decrypt(bytes.fromhex(ciphertext), key)
            plaintext = message.decode("utf-8")
            if args.output_file is not None:
                Path(args.output_file).write_text(plaintext, encoding="utf-8")
            print(plaintext)
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            parser.error(str(exc))


if __name__ == "__main__":
    main()
