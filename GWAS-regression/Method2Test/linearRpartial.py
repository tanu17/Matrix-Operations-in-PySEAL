import random
import math
import os
#import scipy
#from scipy.stats import norm
import numpy
import time
#import threading
import seal
import gc

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
	l=len(row)
	for i in range(l):
		# multiply/binary operation between vectors
		# can define new dit-vector operation here
		cVec=Ciphertext()
		evaluator.multiply(row[i], col[i], cVec)
		evaluator.add(empty_ctext, cVec)

def raise_power(M):
	return(matMultiply(M,M))

def matMultiply(T,K):
	X=[]
	tK=[list(tup) for tup in zip(*K)]
	for i in range(len(T)):
		x=[]
		for j in range(len(K)):
			temp=Ciphertext()
			encryptor.encrypt(encoderF.encode(0), temp)
			dot_vector(T[i], tK[j], temp)
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

def normalize(M):
	for row in M:
		sumTotal=0
		count=0
		for element in row:
			try:
				sumTotal+=int(element)
				element=int(element)
				count+=1
			except:
				continue
		avg=sumTotal/count
		for i in range(len(row)):
			try:
				row[i]=int(row[i])
			except:
				row[i]=avg
		maxR=max(row)
		minR=min(row)
		for i in range(len(row)):
			row[i]= (row[i] - minR) / avg
	return(M)

def inverseMatrix(K):
	n=len(K)
	matrixPower_vector=[K]
	trace_vector=[trace(K)]

	for i in range(1,n):
		matrixPower_vector.append(raise_power(matrixPower_vector[i-1]))
		trace_vector.append(trace(matrixPower_vector[i]))

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

	matrixPower_vector=[iden_matrix(n)]+matrixPower_vector
	c0=Ciphertext()
	encryptor.encrypt(encoderF.encode(1),c0)
	c=[c0]+c

	K_inv=[]
	for i in range(n):
		k_i=[]
		for j in range(n):
			enc_dat=Ciphertext()
			encryptor.encrypt(encoderF.encode(0), enc_dat)
			k_i.append(enc_dat)
		K_inv.append(k_i)

	# Adding the matrices multiplie by their coefficients
	for i in range(len(matrixPower_vector)-1):
		for j in range(len(c)):
			if (i+j == n-1):
				mult(c[j],matrixPower_vector[i])
				for t in range(n):
					for s in range(n):
						evaluator.add(K_inv[t][s],matrixPower_vector[i][t][s])

	determinant= c[n]
	# have to multiply K_inv with 
	return(K_inv,det, determinant)


def create_Empty_CipherMat(M):
	print("-"*20 + "inside create_CipherMat(M)" + "-"*20)
	X=[]
	for i in range(nrow):
		x=[]
		for j in range(ncol):
			x.append(Ciphertext())
		X.append(x)
	gc.collect()
	print("created empty cipher matrix")
	return(X)

def encode_Matrix(M):
	row=len(M)
	col=len(M[0])
	X=[]
	for i in range(row):
		x=[]
		for j in range(col):
			x.append(encoderF.encode(M[i][j]))
		X.append(x)
	return(X)

def encrypt_matrix_row(list_row, row_number):
	print(row_number)
	for j in range(n):
			try:
				encryptor.encrypt(list_row[j], tS_encrypted[row_number][j])
			except Exception as e: 
				print(e)
				break

def encrypt_fullMatrix(M):
	tM= [list(tup) for tup in zip(*M)]
	del(M)
	ncol=len(tM)
	for i in range(ncol):
		encrypt_matrix_row(tM[i], i)
	print("outside the loop")
	return(tM)

parms = EncryptionParameters()
parms.set_poly_modulus("1x^8192 + 1")
parms.set_coeff_modulus(seal.coeff_modulus_128(8192))
parms.set_plain_modulus(1 << 21)
context = SEALContext(parms)

encoderF = FractionalEncoder(context.plain_modulus(), context.poly_modulus(), 30, 34, 3) 
keygen = KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()

encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)

dir_path=os.path.dirname(os.path.realpath(__file__))

snp = open(dir_path+"/snpMat.txt","r+")
S=[]
for row in snp.readlines():
	S.append(row.strip().split())
S=S[1:]
S = numpy.array(S).astype(numpy.float)
S.tolist()

n= len(S) # n=245
m= len(S[0])# m=10643

S_encoded=encode_Matrix(S)
del(S)
gc.collect()
print("matrix has been encoded")


covariate= open(dir_path+"/covariates.csv")
# appending with average in data where NA is there
cov=[]
for row in covariate.readlines():
	cov.append(row.strip().split(","))
cov=cov[1:]
cov_sum=[[0,0],[0,0],[0,0]]
for i in range (len(cov)):
	for j in range(2,5):
		if cov[i][j]!="NA":
			cov_sum[j-2][0]+=int(cov[i][j])
			cov_sum[j-2][1]+=1
cov_new=[]
for i in range(len(cov)):
	cov_new_row=[]
	for j in range(1,5):
		if cov[i][j] =="NA":
			cov_new_row.append(cov_sum[j-2][0]/cov_sum[j-2][1])
		else:
			cov_new_row.append(int(cov[i][j]))
	cov_new.append(cov_new_row)
cov=cov_new
del(cov_new)
gc.collect()
Tcov= [list(tup) for tup in zip(*cov)]
y= Tcov[1][1:]
rawX0= Tcov[2:5]


# encrypting S to S_encrypt
S_encrypted= create_Empty_CipherMat(S_encoded)
tS_encrypted=[list(tup) for tup in zip(*S_encrypted)]
del(S_encrypted)
encrypt_fullMatrix(S_encoded)
print("asdk;vknasifnbsdf")

normalize(rawX0)
# have to find a way to make normalize an encrytped function

for i in range(len(rawX0)):
	rawX0[i]=rawX0[i][1:]
tX=[[1]*245]+ rawX0

# encrypting matrix tX
tX_encrypted=[]
for i in range(n):
	tx_enc=[]
	for j in range(m):
		temp=Ciphertext()
		encryptor.encrypt(encoderF.encode(S_encoded[i][j]), temp)
		tx_enc.append(temp)
	tX_encrypted.append(tx_enc)

X=[list(tup) for tup in zip(*tX)]

for i in range(len(y)):
	temp=Ciphertext()
	encryptor.encrypt(encoderF.encode(int(y[i])), temp)
	y[i]=temp


k= len(X[0]) # k =3

print("here1")
U1= matMultiply(tX_encrypted,y)
cross_X= matMultiply(tX_encrypted,X)

print("here2")

print("Size to inverse: ", len(cross_X))
X_Str, determinant_X_str=inverseMatrix(cross_X)

U2=matMultiply(X_Str, U1)

print("here3")

y_str= numpy.subtract(y,numpy.matmul(X,U2))
#y_str.tolist()

U3= numpy.matmul(tX,S)
U4= numpy.matmul(X_Str, U3)

S_str=numpy.subtract(S,numpy.matmul(X,U4))

S_str2=numpy.square(S_str).sum(axis=0)

tY_str=numpy.transpose(y_str)
b_temp=numpy.matmul(tY_str, S_str)

b=numpy.divide(b_temp, S_str2)

y_str2= numpy.square(y_str)
b2= numpy.square(b)
sig = numpy.subtract(numpy.sum(y_str2),numpy.multiply(b2,S_str2)) / (n-k-2)

err= numpy.sqrt(sig*(1/S_str2))

f=numpy.divide(b,err)
f=-abs(f)
p=[]
for x in f:
	p.append( 1 - (norm(0, 1).cdf(x)) )
logp= -numpy.log10(p)
logp.tolist()

print(len(logp))
