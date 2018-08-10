#import numpy 
import random
import time
import random
#import threading
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
#ev_keys40 = EvaluationKeys
#ev_keys20 = EvaluationKeys()
#keygen.generate_evaluation_keys(40,5,ev_keys40)
#keygen.generate_evaluation_keys(20,3,ev_keys20)
encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)

def print_plain(D):
	# function to print out all elements in a matrix
	for row in D:
		for values in row:
			p=Plaintext()
			decryptor.decrypt(values, p)
			print(encoderF.decode(p))

def print_value(s):
	# print value of an encoded ciphertext
	p=Plaintext()
	decryptor.decrypt(s,p)
	print(encoderF.decode(p))

def trace(M):
	# calculates trace of a matrix 
	t=Ciphertext(M[0][0])
	for i in range(1,n):
		evaluator.add(t,M[i][i])
	return (t)

def dot_vector(row,col,empty_ctext):
	l=len(r)
	for i in range(l):
		# multiply/binary operation between vectors
		# can define new dit-vector operation here
		cVec=Ciphertext()
		evaluator.multiply(row[i], col[i], cVec)
		evaluator.add(empty_ctext, cVec)
		#if (count==2):
		#	evaluator.relinearize(empty_ctext, ev_keys20)

def raise_power(M):
	print("+"*30+"\n")
	X=[]
	for i in range(n):
		# x is rows in matrix X
		x=[]
		for j in range(n):
			temp= Ciphertext()
			encryptor.encrypt(encoderF.encode(0), temp)
			dot_vector(M[i], tA[j],temp)
			print("Noise budget of ["+str(i)+"] ["+str(j)+"] :"+ str(decryptor.invariant_noise_budget(temp)))
			x.append(temp)
		X.append(x)
	return(X)

def mult(s, L):
	# multiplies a matrix L with a scaler s
	for x in L:
		for y in x:
			evaluator.multiply(y,s)

def iden_matrix(n):
	# returns an identity matrix of size n 
	X=[]
	for i in range(n):
		x=[]
		for j in range(n):
			encrypted_data= Ciphertext()
			if (i==j):
				encryptor.encrypt(encoderF.encode(1), encrypted_data)
			else:
				encryptor.encrypt(encoderF.encode(0), encrypted_data)
			x.append(encrypted_data)
		X.append(x)
	return(X)


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


matrixPower_vector=[A]
trace_vector=[trace(A)]
#count=0

# creates vector matrixPower_vector contaning each element as powers of matrix A upto A^n
# Also creates a vector trace_vector which contains trace of matrix A, A^2 ... A^(n-1)
for i in range(1,n):
	matrixPower_vector.append(raise_power(matrixPower_vector[i-1]))
	trace_vector.append(trace(matrixPower_vector[i]))

# Vector c is defined as coefficint vector for the charactersitic equation of the matrix
c=[Ciphertext(trace_vector[0])]
evaluator.negate(c[0])

# The following is the implementation of Newton-identities to calculate the value of coeffecients  
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

matrixPower_vector=[iden_matrix(n)]+matrixPower_vector
c0=Ciphertext()
encryptor.encrypt(encoderF.encode(1),c0)
c=[c0]+c

# Adding the matrices multiplie by their coefficients
for i in range(len(matrixPower_vector)-1):
	for j in range(len(c)):
		if (i+j == n-1):
			mult(c[j],matrixPower_vector[i])
			for t in range(n):
				for s in range(n):
					evaluator.add(A_inv[t][s],matrixPower_vector[i][t][s])

# decrypted inverse matrix
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
# nth coefficient of characteristic equation of th
determin=encoderF.decode(p)

print("negative of co-factor matrix: ",A_i_dec)
A_i_dec=[[(-1/determin)*elem for elem in row] for row in A_i_dec]
print("The inverse matrix:\n",A_i_dec)
