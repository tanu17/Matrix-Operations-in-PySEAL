# linear regression without HE
import random
import math
import scipy
from scipy.stats import norm
import numpy
import time
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
snp = open(dir_path+"/"+"snpMat.txt","r+")
S=[]
for row in snp.readlines():
	S.append(row.strip().split())
S=S[1:]

S = numpy.array(S).astype(numpy.float)

# encrypting matrix S
for index in range(len(S)):
	enc_dat=Ciphertext()
	encryptor.encrypt(encoderF.encode(S[index]), enc_dat, S[index])
print(S)

covariate= open(dir_path+"/"+"covariates.csv")
cov=[]
for row in covariate.readlines():
	cov.append(row.strip().split(","))

cov = numpy.array(cov).astype(numpy.float)
cov.tolist()

Tcov=[list(tup) for tup in zip(*cov)]

y= Tcov[1][1:]
rawX0= Tcov[2:5]

for i in range(len(rawX0)):
	rawX0[i]=rawX0[i][1:]
tX=[[1]*245]+ rawX0

for row in tX:
	for element in row:
		temp=Ciphertext()
		encryptor.encrypt(encoderF.encode(ran), )



normalize(rawX0)

X=[list(tup) for tup in zip(*tX)]

for i in range(len(y)):
	y[i]=int(y[i])


n=len(S) # n=245
m= len(S[0])# m=10643
k= len(X[0]) # k =3

y=numpy.asarray(y)

U1= numpy.matmul(tX,y)
cross_X= numpy.matmul(tX,X)

print("Size to inverse: ", len(cross_X))
X_Str=numpy.linalg.inv(cross_X)
U2=numpy.matmul(X_Str, U1)
#U2.tolist()

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
