# compute a**m mod n
def moduloExp(a, m, n):
     # convert m into binary

     binaryOfm = bin(m)
     binaryOfm = binaryOfm[2:len(binaryOfm)]
     
     d = 1
     k = len(binaryOfm) - 1
     L = range(k,-1,-1)   #L= [k, k-1,...,0]

     for i in L:
          d = d*d%n
          b_i = binaryOfm[k-i]
          if b_i != '0':
               d = (d*a)%n
     return d

def  EuclidGCD(a,b):
     if b > a:
          return EuclidGCD(b,a)
     if b == 0:
          return a
     c = EuclidGCD(b,a%b)
     return c


import primeGenerator
def generatePrime(nOfBits=128):
     return primeGenerator.generatePrime(nOfBits)


def rsaKeyGen(nOfBits=128):
     ### Step 1: genering two primes p, q 
     p = generatePrime(int(nOfBits/2))
     q = generatePrime(int(nOfBits/2))

     # Step 2: compute n= p x q and phi(n)
     n = p*q
     phi_n = (p-1)*(q-1)

     import random

     # Step 3: generate public key
     while True:
          e = random.randrange(1, phi_n) 
          if EuclidGCD(e,phi_n) == 1:
               break

     PU = (e, n)

     ##Step 4: generate private key
     import mulInverseByExtendedEuclidean
     d = mulInverseByExtendedEuclidean.mulInverse(e, phi_n)
     PR = (d, n)
     
     return (PR, PU)


# block encryption algorithm
def encryptBlock(M, K):
     e, n = K
     C = moduloExp(M, e, n)
     # C = M**e%n
     # C = pow(M, e, n)
     return C

# block decryption algorithm
def decryptBlock(C, K):
     d, n = K
     M = moduloExp(C, d, n)
     return M

# multi-block encryption

def encryptBlocks(Ms, K):
     # list comprehension
     return [encryptBlock(M, K) for M in Ms]


# multi-block decryption
def decryptBlocks(Cs, K):
     return [decryptBlock(C, K) for C in Cs]

# bit string encryption algorithm

def encryptBitString(plainBitSeq, K):
     import math
     e, n  = K
     
     blockSize = math.floor(math.log2(n))
   
     Ms = []
     i = 0
     while i<len(plainBitSeq):
          Ms.append(plainBitSeq[i:i+blockSize])
          i = i + blockSize
          
     # perform padding for the last block, which is Ms[len(Ms)-1]
     # print(Ms)

     lM = Ms[len(Ms)-1]
     lM = lM  + "1" + "0"*(blockSize-len(lM)-1)
     Ms[len(Ms)-1] = lM
     #print('binary blocks =', Ms)
     Ms = [int(M,2)  for M in Ms]
     #print('block values =', Ms)

     Cs = encryptBlocks(Ms, K)

     #print('encrypted block values =', Cs)
     
     CsInBinary =  ["0"*(blockSize+1-len(bin(C)[2:])) + bin(C)[2:] for C in Cs]

     #print('encrypted binary values =', CsInBinary)
     
     cipheredBitSeq = ""
     for CInBinary in CsInBinary:
          cipheredBitSeq = cipheredBitSeq +    CInBinary  

     #print(cipheredBitSeq)

     return cipheredBitSeq

# bit string decryption algorithm

def descryptBitString(cipheredBitSeq, K):
     import math
     d, n  = K   
     blockSize = math.floor(math.log2(n))+1
     Cs = []
     i = 0
     while i<len(cipheredBitSeq):
          Cs.append(cipheredBitSeq[i:i+blockSize])
          i = i + blockSize
  
     Cs = [int(C,2) for C in Cs]
     
     Ms = decryptBlocks(Cs, K)
   

     Ms = ["0"*(blockSize-1-len(bin(M)[2:])) + bin(M)[2:] for M in Ms]
     plainBitSeq = "".join(Ms)
     # remove the padded bits
     p = len(plainBitSeq)-1
    
     while True:
          if plainBitSeq[p]=="0":
               p = p -1
          else:
               break
     return plainBitSeq[0:p]



# for textual data
def encryptText(text, K):
     bitString  = "".join(["0"*(8-len(bin(b)[2:])) + bin(b)[2:] for b in text.encode("utf-8")])
     return encryptBitString(bitString,K)

def descryptText(ciphertext, K):
     plainBitString = descryptBitString(ciphertext,K)
     plaintext = ""
     i = 0
     while i < len(plainBitString):
          plaintext =  plaintext + chr(int(plainBitString[i:i+8],2))
          i = i + 8
     return plaintext

# test
#print(descryptText(encryptText("this is a secret", PR), PU))


# ── Byte-level encrypt / decrypt ──────────────────────────────────────────────
# work on raw bytes objects
# encrypt a session key as bytes, not as text.

def _toKeyTuple(K):
    """Accept either a plain (e_or_d, n) tuple OR a pycryptodome RsaKey object.
    
    For a PUBLIC  RsaKey: pass the key directly → extracts (e, n)
    For a PRIVATE RsaKey: pass the key directly → extracts (d, n)
    """
    if isinstance(K, tuple):
        return K                            # already (e, n) or (d, n)
    # pycryptodome RsaKey — private keys have .d, public keys do not
    n = int(K.n)
    if hasattr(K, 'd') and K.has_private():
        return (int(K.d), n)               # private key → (d, n)
    return (int(K.e), n)                   # public key  → (e, n)

def encryptBytes(plainBytes, K):
    K = _toKeyTuple(K)
    e, n = K
    orig_len = len(plainBytes)
    
    # Convert bytes directly to one big integer
    # print(plainBytes)
    m = int.from_bytes(plainBytes, 'big')
    
    # RSA: C = m^e mod n  (one operation — no blocks needed)
    c = moduloExp(m, e, n)
    
    # Convert cipher integer back to bytes
    # +2 for the orig_len header we prepend
    c_bytes = c.to_bytes((c.bit_length() + 7) // 8, 'big')
    
    # Prepend original length so decryption knows exact size to return
    return orig_len.to_bytes(2, 'big') + c_bytes


def decryptBytes(cipherBytes, K):
    K = _toKeyTuple(K)
    d, n = K
    
    # Read header
    orig_len = int.from_bytes(cipherBytes[:2], 'big')
    c_bytes  = cipherBytes[2:]
    
    # Convert cipher bytes to integer
    c = int.from_bytes(c_bytes, 'big')
    
    # RSA: m = c^d mod n
    m = moduloExp(c, d, n)
    
    # Convert back to bytes, truncate to original length
    m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
    return m_bytes[:orig_len]
