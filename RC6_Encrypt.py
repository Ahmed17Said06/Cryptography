#RC6 32/20/X
import math
import ctypes

print("This is the new run ----------------------------------------------------------------------------------")
print()

INT_BITS = 32
 
# Function to left
# rotate n by d bits
def leftRotate(n, d):
    # In n<<d, last d bits are 0.
    # To put first 3 bits of n at
    # last, do bitwise or of n<<d
    # with n >>(INT_BITS - d)
    # to turncate the value to the lowest N bits can be done by using %(1 << N)
    return ((n << d) % (1 << INT_BITS))|(n >> (INT_BITS - d))

PlainText = "02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1"
UserKey   = "01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78"

#Converting the input UserKey to 16 Hexadecimal values
Keys_Hexa = bytearray.fromhex(UserKey)
plaintext_bytes = bytearray.fromhex(PlainText)
Number_of_Bytes_plaintext = len(plaintext_bytes)


w = 32             # Number of bits in the word
r = 20             # Number of rounds
b = len(Keys_Hexa) # Number of bytes in the key

u = int (w/8)      # Number of bytes per word
c = int (b/u)      # Number of words in the L array that wil be used in generating the keys
t = int (2*r + 4)  # Number of random binary words used in S array

# L array that holds the Key in number of c words
L = [0] * c                
L = [0 for i in range(c)]

# Dividing the key to c-words in and save it in the L array
for i in range(b-1,-1,-1):
    h = int(i/u)
    L[h] = (L[h] << 8) + Keys_Hexa[i]

print("the following is the L")
print()

for i in range(0,c,1):
    print("L[",i,"] = ",hex(L[i]))
print()

# The key expansion magic constants
P32 = 0xb7e15163 #Pw = Odd ((e − 2)2^w)
Q32 = 0x9e3779b9 #Qw = Odd ((φ − 1)2^w)

# S array that holds psudorandom bit pattern used in expanding the key to the numebr of rounds
S = [0] * t
S = [0 for i in range(t)]

# Intializing the S- array
S[0] = P32

for i in range(1,t,1):
    S[i] = S[i-1] + Q32
    
# Mixing in the secret key S
x = y = i = j = 0

v = 3 * max (c,t)

for s in range (1,v + 1, 1):
    x = S[i] = leftRotate((S[i] + x + y) % (1 << INT_BITS),3)
    Amount_In_LS_5bits = (x + y) % (1 << 5)
    y = L[j] = leftRotate((L[j] + x + y) % (1 << INT_BITS) ,  Amount_In_LS_5bits)
    
    i = (i + 1) % t
    j = (j + 1) % c

    
print("the following is the S")
print()
for i in range(0,t,1):
    print("S[",i,"] = ",hex(S[i]))
print()

# Encryption

#Chunking the plain text into 4 words each 32 bits.
P = [0] * c                
P = [0 for i in range(c)]

for i in range(len(plaintext_bytes)-1,-1,-1):
    h = int(i/u)
    P[h] = (P[h] << 8) + plaintext_bytes[i]
    
A = P[0]
B = P[1]
C = P[2]
D = P[3]


B = (B + S[0]) % (1 << INT_BITS)
D = (D + S[1]) % (1 << INT_BITS)

# Start of the r rounds
for i in range (1, r + 1, 1):

    t_local = leftRotate(((B * (2*B + 1)) % (1 << INT_BITS)), int(math.log2(w))) % (1 << INT_BITS)
    u_local = leftRotate(((D * (2*D + 1)) % (1 << INT_BITS)), int(math.log2(w))) % (1 << INT_BITS)

    t_local_5bits = (t_local) % (1 << 5)
    u_local_5bits = (u_local) % (1 << 5)

    A = leftRotate((A ^  t_local) , u_local_5bits)  + S[2*i] 
    C = leftRotate((C ^  u_local) , t_local_5bits)  + S[2*i + 1] 

    A = A % (1 << INT_BITS)
    C = C % (1 << INT_BITS)

    A, B, C, D = B, C, D, A
    
    print("A = ", hex(A),"  ","B = ",hex(B), "  ","C = ",hex(C),"  ","D = ",hex(D))

print()

A = A + S[2*r + 2]
C = C + S[2*r + 3]

A = A % (1 << INT_BITS)
C = C % (1 << INT_BITS)

print("The final results of the 4 registers")
print()

print("A = ", hex(A))
print("B = ", hex(B))
print("C = ", hex(C))
print("D = ", hex(D))

print()

# cipher text

CipherText_A = A.to_bytes(4, byteorder = 'little')
CipherText_B = B.to_bytes(4, byteorder = 'little')
CipherText_C = C.to_bytes(4, byteorder = 'little')
CipherText_D = D.to_bytes(4, byteorder = 'little')

CipherText_msg = CipherText_A + CipherText_B + CipherText_C + CipherText_D


print("The Cipher message:")
print()

for i in range(len(CipherText_msg)):
    print ('{:02x}'.format(CipherText_msg[i]), end=" ")

print()



