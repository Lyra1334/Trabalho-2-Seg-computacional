from random import randint, getrandbits

def MillerTest(n : int) -> bool:
    if n <= 3:
        return True
    b = randint(1,n-1)
    k = 1
    q = n-1
    while q%2==0:
        k+=1
        q = q//2
    if pow(b,q,n) == 1:
        return True
    else:
        for i in range(k):
            if pow(b,(pow(2,i))*q,n) == n-1:
                return True
    return False

def GeneratePrimes(mod):
    
    a = getrandbits(mod)
    b = getrandbits(mod)
    while not MillerTest(a):
        a = getrandbits(mod)
    while (not MillerTest(b) or a==b):
        b = getrandbits(mod)
    return a, b

def MDC(a:int, b:int):
    if a < b:
        a,b = b,a
    while a%b != 0:
        a,b = b, a%b
    return b

def GenerateD(e:int, phi:int):
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
