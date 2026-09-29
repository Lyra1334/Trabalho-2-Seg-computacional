Programa de linha de comando para gerar chaves RSA e cifrar ou decifrar mensagens com OAEP.

Exemplos de uso:
python rsa_key_cli.py keygen --key-size 1024
python rsa_key_cli.py encrypt -k rsa_key_pub.txt "Olá, mundo!"
python rsa_key_cli.py decrypt -k rsa_key_priv.txt HEX_GERADO_PELO_COMANDO_ENCRYPT
python rsa_key_cli.py encrypt -k rsa_key_pub.txt -i mensagem.txt -o mensagem_cifrada.txt
python rsa_key_cli.py decrypt -k rsa_key_priv.txt -i mensagem_cifrada.txt -o mensagem_decifrada.txt
