import random
import math
import os
import numpy
import time
import seal
import gc
try:
    import cPickle as pickle
except ModuleNotFoundError:
    import pickle

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

############################ matrixEncryptRows ####################################


class matrixEncryptRows:
	
	def __init__(self, starting_rowNumber, encodedRows):
		self.i= starting_rowNumber
		#self.S_block= encodedRows
		self.nrow= len(encodedRows)
		self.ncol= len(encodedRows[0])
		self.X=[]
		self.encrypt_matrix_row(encodedRows)

	def encrypt_matrix_row(self,encodedRows):
		for i in range(self.nrow):
			x=[]
			for j in range(self.ncol):
				x.append(Ciphertext())
			self.X.append(x)

		for rowI in range(self.nrow):
			for colI in range(self.ncol):
				encryptor.encrypt(encodedRows[rowI][colI], self.X[rowI][colI])

	def __del__(self):
		with open(str(self.i)+'.matrix', 'wb') as f:
			pickle.dump(self,f)

########################## matrixOperations ######################################

class matrixOperations:

	@staticmethod
	def dot_vector(row,col,empty_ctext):
	#returns dot vector between two vectors
		l=len(row)
		for i in range(l):
			# multiply/binary operation between vectors
			# can define new dot-vector operation(linear algebra) here
			cVec=Ciphertext()
			evaluator.multiply(row[i], col[i], cVec)
			evaluator.add(empty_ctext, cVec)

	@staticmethod
	def matMultiply(T,K):
	# multipliess two matrix and returns a new matrix as result
		X=[]
		rowK=len(K)
		K_vector=0
		T_vector=0
		if (type(K[0]) != list ):
			tK=K
			print("Dimension of T: %dx%d\nDimension of K: %dx1"%(len(T),len(T[0]),len(K)))
			K_vector=1

		elif (type(T[0]) != list ):
			tK=[list(tup) for tup in zip(*K)]
			print("Dimension of T: %dx1\nDimension of K: %dx%d"%(len(T),len(K),len(K[0])))
			T_vector=1

		else:
			tK=[list(tup) for tup in zip(*K)]
			print("Dimension of T: %dx%d\nDimension of K: %dx%d"%(len(T),len(T[0]),len(K),len(K[0])))
		del(K)
		for i in range(len(T)):
			x=[]
			for j in range(rowK):
				temp=Ciphertext()
				encryptor.encrypt(encoderF.encode(0), temp)
				if (K_vector==1):
					matrixOperations.dot_vector(T[i], tK, temp)
				elif(T_vector==1):
					matrixOperations.dot_vector(T, tK[j], temp)
				else:
					matrixOperations.dot_vector(T[i], tK[j], temp)
				x.append(temp)
			X.append(x)
		return(X)

	@staticmethod
	def multScaler(s, L):
	# multiplies a matrix L with a scaler s, changes the same matrix
		for x in L:
			for y in  x:
				evaluator.multiply(y,s)

	@staticmethod
	def trace(M):
	# calculates trace of a matrix 
		t=Ciphertext(M[0][0])
		for i in range(1,n):
			evaluator.add(t,M[i][i])
		return (t)

	@staticmethod
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

	@staticmethod
	def subtractMatrix(T,K):
		for i in range(len(T)):
			for j in range(len(T[0])):
				evaluator.sub(T[i][j], K[i][j])

	@staticmethod
	def colSquare_Sum(M):
		tM = [list(tup) for tup in zip(*M)]
		del(M)
		X=[] 
		rowM=len(tM)
		for i in range(rowM):
			x=Ciphertext()
			encryptor.encrypt(encoderF.encode(0),x)
			for element in (tM[i]):
				y=Ciphertext()
				evaluator.square(element,y)
				evaluator.add(y,x)
			X.append(x)
		return(X)

	@staticmethod
	def inverseMatrix(K):
		n=len(K)
		matrixPower_vector=[K]
		trace_vector=[matrixOperations.trace(K)]

		for i in range(1,n):
			matrixPower_vector.append(matrixOperations.matMultiply(matrixPower_vector[i-1]),matrixPower_vector[0])
			trace_vector.append(matrixOperations.trace(matrixPower_vector[i]))

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

		matrixPower_vector=[matrixOperations.iden_matrix(n)]+matrixPower_vector
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
					matrixOperations.multScaler(c[j],matrixPower_vector[i])
					for t in range(n):
						for s in range(n):
							evaluator.add(K_inv[t][s],matrixPower_vector[i][t][s])

		determinant= c[n]
		# have to multiply K_inv with 
		return(K_inv, determinant)

	@staticmethod
	def multiplyDeterminant(M, determinant):
		p=Plaintext()
		# need to send user D so that user can send back -1/D either in encrypted form or decrypted form
		decryptor.decrypt(determinant, p)
		d= (-1/encoderF.decode(p))
		delta=encoderF.encode(d)
		for i in range(len(M)):
			for j in range(len(M[0])):
				evaluator.multiply_plain(M[i][j], delta)


########################## rest of functions neeeded ###########################


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

def reconstructMatrix():
	global S_encRECON
	for i in range(0,4,2):
		target=str(i)+'.matrix'
		if os.path.getsize(target)>0:
			with open(target, 'rb') as f:
				print("opened")
				row2=pickle.load(f)
				S_encRECON+=row2.X
				f.close()
		else:
			print("[-] Error occured while reconstructing matrix")

def decrypt_matrix(M):
	M_dec=[]
	for x in M:
		m=[]
		for y in x:
			p=Plaintext()
			decryptor.decrypt(y, p)
			m.append(encoderF.decode(p))
		M.append(m)
	return(M)


########################## paramaters required #################################

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

########################## encoding main matrix ################################



A=[Ciphertext(),Ciphertext(),Ciphertext(),Ciphertext()]

for i in range(len(A)):
	encryptor.encrypt(encoderF.encode(i), A[i])

for j in range(10):
	evaluator.multiply(A[0],A[1])
	evaluator.multiply(A[0],A[2])
	evaluator.add(A[1],A[2])
	for i in range(len(A)):
		print("Noise budget of ["+ str(i)+"] :"+str((decryptor.invariant_noise_budget(A[i]))) + " bits")
		print("A[%d]: "%(i),)
		print_value(A[i])
