from random import randint, getrandbits

SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)

def MillerTest(n : int) -> bool:
    #Teste de miller pra ver se um número é provavelmente primo.
    #Implementado de acordo com: https://schcs.github.io/WP/index.php/ensino/fundamentos-de-algebra/o-teste-de-primalidade-de-miller/
    if n < 2:
        return False
    for prime in SMALL_PRIMES:
        if n == prime:
            return True
        if n % prime == 0:
            return False
    b = randint(2,n-2)
    k = 1
    q = n-1
    while q%2==0:
        k+=1
        q = q//2
    #A gente decompõe n-1 no formato (2^k)*q onde q é um número ímpar.
    if pow(b,q,n) == 1:
        return True
    #Condição 1 pra n ser primo: (b^q)%n == 1

    else:
        for i in range(k):
            if pow(b,(pow(2,i))*q,n) == n-1:
                #Condição 2: b^((2^i)*q)%n == -1, para algum i de 0 a k-1.
                return True
    return False

def GeneratePrimes(mod):
    #Gera os dois numeros primos e diferentes entre si.
    def candidate():
        return getrandbits(mod) | (1 << (mod - 1)) | 1

    a = candidate()
    b = candidate()
    while not MillerTest(a):
        a = candidate()
    while (not MillerTest(b) or a==b):
        b = candidate()
    return a, b

def MDC(a:int, b:int):
    #Usado pra testar co-primalidade, pelo algoritmo de euclides
    if a < b:
        a,b = b,a
    while a%b != 0:
        a,b = b, a%b
    return b

def GenerateD(e:int, phi:int):
    #Algoritmo de euclides extendido. Serve pra descobrir o inverso multiplicativo de e.
    r_atual = phi
    r_novo = e
    u_atual = 1
    v_atual = 0
    u_novo = 0
    v_novo = 1
    r_antigo = 0
    u_antigo = 0
    v_antigo = 0
    quociente = 0

    while r_novo != 0:
        quociente = int(r_atual/r_novo)
        r_antigo = r_atual
        u_antigo = u_atual
        v_antigo = v_atual
        r_atual = r_novo
        u_atual = u_novo
        v_atual = v_novo
        r_novo = r_antigo - quociente*r_novo
        u_novo = u_antigo - quociente*u_novo
        v_novo = v_antigo - quociente*v_novo
    return v_atual



def GenerateE(phi:int):
    e = randint(1,phi)
    mdc = MDC(e,phi)
    while mdc != 1:
        e = randint(1,phi)
        mdc = MDC(e,phi)
    #Gera um E novo entre 1 e phi até e ser co-primo de phi.
    return e

def generateKeyPair(mod:int, file_path:str):
    p, q = GeneratePrimes(mod)
    phi = (p-1)*(q-1)
    e = GenerateE(phi)
    d = GenerateD(e, phi)
    with open(file_path+"_pub.txt","w") as publica:
        publica.write(f"{p*q}\n{e}")
    with open(file_path+"_priv.txt","w") as privada:
            privada.write(f"{p}\n{q}\n{d}")
