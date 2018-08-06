#import numpy 
import random
import copy
import time
import random
import threading
import seal

from seal import ChooserEvaluator,     \
                 Ciphertext,           \
                 Decryptor,            \
                 Encryptor,            \
                 EncryptionParameters, \
                 Evaluator,            \
                 IntegerEncoder,       \
                 FractionalEncoder,    \
                 KeyGenerator,         \
                 MemoryPoolHandle,     \
                 Plaintext,            \
                 SEALContext,          \
                 EvaluationKeys,       \
                 GaloisKeys,           \
                 PolyCRTBuilder,       \
                 ChooserEncoder,       \
                 ChooserEvaluator,     \
                 ChooserPoly

parms = EncryptionParameters()
parms.set_poly_modulus("1x^16384 + 1")
parms.set_coeff_modulus(seal.coeff_modulus_128(16384))
parms.set_plain_modulus(1 << 16)
context = SEALContext(parms)

encoder = IntegerEncoder(context.plain_modulus())
keygen = KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()
ev_keys20 = EvaluationKeys()
keygen.generate_evaluation_keys(20,ev_keys20)
encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)

A=[]
X=[]
n=int(input("Enter dimension: "))

for i in range(n):
	a=[]
	x=[]
	for j in range(n):
		encrypted_data1= Ciphertext()
		encrypted_data2= Ciphertext()
		ran=random.randint(0,10)
		print(ran)
		encryptor.encrypt(encoder.encode(ran), encrypted_data1)
		encryptor.encrypt(encoder.encode(0), encrypted_data2)
		a.append(encrypted_data1)
		x.append(encrypted_data2)
	A.append(a)
	X.append(x)

#tA_=numpy.transpose(A)
tA=[list(tup) for tup in zip(*A)]

def dot_vector(r,d,i,j):
	print("+"*30+"\n")
	l=len(r)
	for b in range(l):
		# multiply/binary operation between vectors
		cVec=Ciphertext()
		if (count>2):
			evaluator.relinearize(r[b], ev_keys20)
			evaluator.relinearize(d[b], ev_keys20)
		evaluator.multiply( r[b], d[b], cVec)
		evaluator.add(X[i][j], cVec)
	print("Noise budget "+str(i)+" "+str(j)+" "+ str(decryptor.invariant_noise_budget(X[i][j])))


def raise_power(M):
	for i in range(n):
		for j in range(n):
			dot_vector(M[i], tA[j], i, j)
	return(X)

def trace(M):
	e=Ciphertext()
	encryptor.encrypt(encoder.encode(0), e)
	for i in range(0,n):
		evaluator.add(e,M[i][i])
	return (e)

def print_plain(D):
	for x in D:
		for y in x:
			p=Plaintext()
			decryptor.decrypt(y, p)
			print(encoder.decode_int32(p))


matrixPower_vector=[A]
trace_vector=[trace(A)]
count=1
for i in range(1,n-1):
	matrixPower_vector.append(raise_power(matrixPower_vector[i-1]))
	trace_vector.append(trace(matrixPower_vector[i]))
	count+=1

for y in (matrixPower_vector):
	print_plain(y)

