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
parms.set_poly_modulus("1x^8192 + 1")
parms.set_coeff_modulus(seal.coeff_modulus_128(8192))
parms.set_plain_modulus(1 << 21)
context = SEALContext(parms)

#encoder = IntegerEncoder(context.plain_modulus())
encoderF = FractionalEncoder(context.plain_modulus(), context.poly_modulus(), 30, 34, 3) 
keygen = KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()
ev_keys40 = EvaluationKeys()
ev_keys20 = EvaluationKeys()
#keygen.generate_evaluation_keys(40,5,ev_keys40)
#keygen.generate_evaluation_keys(20,3,ev_keys20)
encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)

A=[]
A_inv=[]
n=int(input("Enter dimension: "))

for i in range(n):
	a=[]
	a_i=[]
	for j in range(n):
		encrypted_data1= Ciphertext()
		enc_dat=Ciphertext()
		ran=random.randint(0,10)
		print(ran)
		encryptor.encrypt(encoderF.encode(ran), encrypted_data1)
		encryptor.encrypt(encoderF.encode(0), enc_dat)
		a.append(encrypted_data1)
		a_i.append(enc_dat)
	A.append(a)
	A_inv.append(a_i)

#tA_=numpy.transpose(A)
tA=[list(tup) for tup in zip(*A)]

def dot_vector(r,d,i,j, empty_ctext):
	l=len(r)
	for b in range(l):
		# multiply/binary operation between vectors
		cVec=Ciphertext()
		evaluator.multiply(r[b], d[b], cVec)
		evaluator.add(empty_ctext, cVec)
		#if (count==2):
		#	evaluator.relinearize(empty_ctext, ev_keys20)
	print("Noise budget "+str(i)+" "+str(j)+" "+ str(decryptor.invariant_noise_budget(empty_ctext)))


def raise_power(M):
	print("+"*30+"\n")
	X=[]
	for i in range(n):
		x=[]
		for j in range(n):
			encrypted_data2= Ciphertext()
			encryptor.encrypt(encoderF.encode(0), encrypted_data2)
			dot_vector(M[i], tA[j], i,j,encrypted_data2)
			x.append(encrypted_data2)
		X.append(x)
	return(X)

def trace(M):
	e=Ciphertext() 
	encryptor.encrypt(encoderF.encode(0), e)
	for i in range(0,n):
		evaluator.add(e,M[i][i])
	return (e)

def print_plain(D):
	for x in D:
		for y in x:
			p=Plaintext()
			decryptor.decrypt(y, p)
			print(encoderF.decode(p))
def print_value(s):
	p=Plaintext()
	decryptor.decrypt(s,p)
	print(encoderF.decode(p))

def mult(s, L):
	for x in L:
		for y in x:
			evaluator.multiply(y,s)

def iden_matrix(n):
	X=[]
	for i in range(n):
		x=[]
		for j in range(n):
			encrypted_data2= Ciphertext()
			if (i==j):
				encryptor.encrypt(encoderF.encode(1), encrypted_data2)
			else:
				encryptor.encrypt(encoderF.encode(0), encrypted_data2)
			x.append(encrypted_data2)
		X.append(x)
	return(X)


matrixPower_vector=[A]
trace_vector=[trace(A)]
#count=0
for i in range(1,n):
	matrixPower_vector.append(raise_power(matrixPower_vector[i-1]))
	trace_vector.append(trace(matrixPower_vector[i]))
	
"""
print(len(trace_vector))
print(len(matrixPower_vector))

for y in (trace_vector):
	p=Plaintext()
	decryptor.decrypt(y, p)
	print(encoderF.decode(p))
"""

c=[Ciphertext(trace_vector[0])]
evaluator.negate(c[0])

for i in range(1,n):
	c_new=Ciphertext(trace_vector[i])
	for j in range(i):
		tc=Ciphertext()
		evaluator.multiply(trace_vector[i-1-j],c[j],tc)
		evaluator.add(c_new,tc)
	evaluator.negate(c_new)
	frac=encoderF.encode(1/(i+1))
	evaluator.multiply_plain(c_new,frac)
	c.append(c_new)
	

for i in range(n):
	print("t"+str(i))
	print_value(trace_vector[i])
	print_value(c[i])

matrixPower_vector=[iden_matrix(n)]+matrixPower_vector
c0=Ciphertext()
encryptor.encrypt(encoderF.encode(1),c0)
c=[c0]+c

for i in range(len(matrixPower_vector)-1):
	for j in range(len(c)):
		if (i+j == n-1):
			mult(c[j],matrixPower_vector[i])
			#print_plain(matrixPower_vector[i])
			#print("c[j]= "),
			#print_value(c[j])
			for t in range(n):
				for s in range(n):
					evaluator.add(A_inv[t][s],matrixPower_vector[i][t][s])

A_i_dec=[]
for x in A_inv:
	a_i=[]
	for y in x:
		p=Plaintext()
		decryptor.decrypt(y, p)
		a_i.append(encoderF.decode(p))
	A_i_dec.append(a_i)

p_deter=Plaintext()
decryptor.decrypt(c[n], p)
determin=encoderF.decode(p)
print(A_i_dec)
A_i_dec=[[(-1/determin)*elem for elem in row] for row in A_i_dec]
print(A_i_dec)
