#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy as np
import itertools, time
import random,math,gc
import seal
#import multiprocessing 
from seal import Ciphertext,           \
                 Decryptor,            \
                 Encryptor,            \
                 EncryptionParameters, \
                 Evaluator,            \
                 FractionalEncoder,    \
                 KeyGenerator,         \
                 MemoryPoolHandle,     \
                 Plaintext,            \
                 SEALContext,          \
                 EvaluationKeys


def readNoiseBudget(enc_num):
    sTime = time.time()
    remain = decryptor.invariant_noise_budget(enc_num)
    return remain

def plainMultiplication(element, d):
	delta = encoderF.encode(d)
	temp = Ciphertext()
	evaluator.multiply_plain(element, delta, temp)
	evaluator.relinearize(temp, ev_keys)
	return(temp)


def decryption_num(element):
	p = Plaintext()
	decryptor.decrypt(element, p)
	temp = encoderF.decode(p)
	return(temp)

def encryption_num(element):
	temp = Ciphertext()
	encryptor.encrypt(encoderF.encode(element), temp)
	return(temp)

def encrypt_matrix(M):
	# assume the input is a numpy array
	#sTime = time.time()
	enc_M = []
	for element in M.flatten():
		enc_M.append(encryption_num(element))
	enc_M = np.asarray(enc_M)
	enc_M = enc_M.reshape(M.shape)
	#print('Encrypting a {} matrix costs {:.2f} seconds'.format(M.shape, time.time()-sTime))
	return(enc_M)

def decrypt_matrix(M):
	# assume the input is a numpy array
	#sTime = time.time()
	dec_M = []
	try:
		for element in M.flatten():
			dec_M.append(decryption_num(element))
		dec_M = np.asarray(dec_M)
		dec_M = dec_M.reshape(M.shape)
	#    print('Decrypting a {} matrix costs {:.2f} seconds'.format(M.shape, time.time()-sTime))
	except:
		for element in M:
			dec_M.append(decryption_num(element))
		dec_M = np.asarray(dec_M)
		#print('Decrypting a {} matrix costs {:.2f} seconds'.format(M, time.time()-sTime))
	print(dec_M)
	#return(dec_M)

def multiplication(element1, element2):
	temp = Ciphertext()
	evaluator.relinearize(element1, ev_keys)
	evaluator.relinearize(element2, ev_keys)
	evaluator.multiply(element1, element2, temp)
	evaluator.relinearize(temp, ev_keys)
	return(temp)

def vectorMultiply(T, K):
	assert(1 == len(T.shape))
	assert(1 == len(K.shape))
	assert(T.shape == K.shape)
	P = []
	for i in range(len(T)):
		P.append(multiplication(T[i], K[i]))

	sumP = Ciphertext()
	evaluator.add_many(P, sumP)
	evaluator.relinearize(sumP, ev_keys)
	return(sumP)

def matrixMultiply(T, K, symmetric=0):
	if 1 == len(T.shape):   # T is a vector
		T = T[np.newaxis]
	if 1 == len(K.shape):   # K is a vector
		K = K[:, np.newaxis]
	#sTime = time.time()
	try:
		assert(T.shape[1] == K.shape[0])
	except:
		print("T:")
		print(len(T))
		print(len(T[0]))
		print("K:")
		print(len(K))
		print(len(K[0]))

	nRow = T.shape[0]
	nCol = K.shape[1]

	P = []
	tK = K.T
	if (symmetric):
		P= [[0 for z in range(nRow)] for q in range(nRow)]
		for i in range(nRow):
			for j in range(i+1):
				P[i][j]= vectorMultiply(T[i], tK[j])
				if (i!=j):
					P[j][i]= Ciphertext(P[i][j])
	else:
		for i in range(nRow):
			for j in range(nCol):
				P.append(vectorMultiply(T[i], tK[j]))
	P = np.asarray(P)
	P = P.reshape((nRow, nCol))

	#print('Multiplying a {} matrix with a {} matrix costs {:.2f} seconds'.format(T.shape, K.shape,time.time()-sTime))
	return(P)

def hadamardProduct_trace(X, Y):
	"""
	X_lower= X[numpy.nonzero(numpy.tril(X,-1))]
	Y_lower= Y[numpy.nonzero(numpy.tril(Y,-1))]
	
	sum1= plainMultiplication(vectorMultiply(X_lower,Y_lower),2)
	sum2= vectorMultiply(numpy.diag(X),numpy.diag(Y))
	evaluator.add(sum1,sum2)
	return(sum2)
	"""
	return vectorMultiply(X.flatten(), Y.flatten())

def coefficientPolyCreate(trace_vector, N):
	coeff=[Ciphertext(trace_vector[0])]
	evaluator.negate(coeff[0])
	for i in range(1,N):
		if(i==N-1):
			#print("N-1")
			c_new= Ciphertext()
			Q= [Ciphertext(trace_vector[i])]
			for j in range(i):
				temp= multiplication(coeff[j], trace_vector[i-j-1])
				#print(readNoiseBudget(coeff[j]),readNoiseBudget(trace_vector[i-j-1]))
				Q.append(temp)
			evaluator.add_many(Q, c_new)
			try:
				evaluator.relinearize(c_new, ev_keys)
			except:
				pass
				print("pass")
			frac= encoderF.encode(-1/(i+1))
			evaluator.multiply_plain(c_new, frac)
			coeff.append(c_new)
			#print(readNoiseBudget(c_new))
		else:
			c_new= Ciphertext()
			Q= [Ciphertext(trace_vector[i])]
			for j in range(i):
				temp= multiplication(coeff[j], trace_vector[i-j-1])
				Q.append(temp)
			evaluator.add_many(Q, c_new)
			try:
				evaluator.relinearize(c_new, ev_keys)
			except:
				pass
				print("pass")
			frac= encoderF.encode(-1/(i+1))
			evaluator.multiply_plain(c_new, frac)
			coeff.append(c_new)

	c0=Ciphertext()
	encryptor.encrypt(encoderF.encode(1),c0)
	coeff=[c0]+coeff
	decrypt_matrix(coeff)
	return(coeff)

def iden_matrix(n):
	# returns an identity matrix of size n 
	plain_X= np.identity(n)
	return encrypt_matrix(plain_X)

def trace(M):
	t=Ciphertext()
	diag = np.diag(M)
	evaluator.add_many(diag, t)
	return (t)

def TraceCalculation(Power_vector_Half):
	N= Power_vector_Half[0].shape[0]
	traceVec=[]

	for i in range(1,len(Power_vector_Half)):
		traceVec.append(trace(Power_vector_Half[i]))

	if (N%2 ==0):
		for i in range(N//4 + 1, N//2 +1):
			if(2*i-1 > len(traceVec)):
				traceVec.append(hadamardProduct_trace(Power_vector_Half[i],Power_vector_Half[i-1]))
			traceVec.append(hadamardProduct_trace(Power_vector_Half[i],Power_vector_Half[i]))
	else:
		for i in range(N//4 + 1, N//2 +2):
			if (i> N//4 + 1):
				#print(i,2*i-1)
				traceVec.append(hadamardProduct_trace(Power_vector_Half[i],Power_vector_Half[i-1]))
			if (N> 2*i and 2*i>N//2 +1):
				#print(i,2*i)
				traceVec.append(hadamardProduct_trace(Power_vector_Half[i],Power_vector_Half[i]))

	return(traceVec)

def Power_vector_HalfCalculation(M):
	# Power_vector_Half= [ I, M, M^2, M^3,....M^[(n+1)/2] ]
	Power_vector_Half= [M]
	N= M.shape[0]

	for i in range(1, (len(M)+1)//2):
		Power_vector_Half.append(matrixMultiply(M, Power_vector_Half[i-1], symmetric=1))
	Power_vector_Half= [iden_matrix(N)]+ Power_vector_Half
	return(Power_vector_Half)

def multiplyDeterminant(M, determinant):
	p=Plaintext()
	# need to send user D so that user can send back -1/D either in encrypted form or decrypted form
	decryptor.decrypt(determinant, p)
	d= (-1/encoderF.decode(p))
	#delta=encoderF.encode(d)
	
	assert(list == type(M))
	M_flatten = list(element for m in M for element in m)

	X_flatten = []
	for item in M_flatten:
		X_flatten.append(plainMultiplication(item, d))
	return(X_flatten)



def inverseMatrix(M):
	n = len(M)
	Power_vector_Half = Power_vector_HalfCalculation(M)
	trace_vector = TraceCalculation(Power_vector_Half)
	coefficientPoly = coefficientPolyCreate(trace_vector, n)

	M_inverse = []
	determinant = coefficientPoly.pop()
	print("determinant by HE: ",decryption_num(determinant))

	# x = [0]*n-i-1 + [1] + [0]*i
	for i in range(n-1, -1, -1):
		powerMatrix_X = []
		for j in range(len(Power_vector_Half)):
			#a= Power_vector_Half[j][i]
			powerMatrix_X.append(Power_vector_Half[j][i])
			#decrypt_matrix(a)
		# multiplies x with powers I, A, A^2 ... A^( [n/2  + 0.5] )

		for j in range(len(Power_vector_Half), n):
		# to avoid budget of only one matrix to go down, we randomly choose vector. 
		# differece will be noticable when matrix is large, here n is 4, so wont matter much here
			partition_1 = random.randint(n//4+1, n//2)
			if (j-partition_1 >= len(Power_vector_Half)):
				partition_1 = len(Power_vector_Half)-1
			partition_2 = j - partition_1
			multiplier1 = Power_vector_Half[partition_1][:i+1]
			multiplier2 = Power_vector_Half[partition_2][i]
			Z = matrixMultiply(multiplier1, multiplier2)
			powerMatrix_X.append(list(Z.flatten()))
		# powerMatrix_X is powerMatrix multiplied by x vector

		for j in range(len(powerMatrix_X)):
			powerMatrix_X[j] = powerMatrix_X[j][:i+1]
			for l in range(len(powerMatrix_X[j])):
				evaluator.multiply(powerMatrix_X[j][l], coefficientPoly[n-1-j])
				evaluator.relinearize(powerMatrix_X[j][l], ev_keys)

		tInverseRow = [list(tup) for tup in zip(*powerMatrix_X)]
		InverseRow = []
		for z in range(len(tInverseRow)):
		    temp = Ciphertext()
		    evaluator.add_many(tInverseRow[z], temp)
		    InverseRow.append(temp)

		M_inverse.append(InverseRow)

	M_inverse = multiplyDeterminant(M_inverse, determinant)
	assert( n*(n+1)/2 == len(M_inverse) )
	# recontruct the lower triangle
	X = []
	sInd = 0
	for i in range(n):
		X.append(M_inverse[sInd:sInd+n-i])
		sInd += n-i
	X.reverse()
	# complete the symmetric matrix
	for rowIndex in range(n):
		assert( len(X[rowIndex]) <= n )
		X[rowIndex] += [None]*(n-len(X[rowIndex]))
	for rowIndex in range(n):
		for colIndex in range(rowIndex+1, n):
			assert( X[rowIndex][colIndex]==None )
			X[rowIndex][colIndex] = X[colIndex][rowIndex]

	X_array = np.asarray(X)
	return(X_array)


########################## paramaters required #################################


#N= int(input("Enter dimension of matrix needed to reverse: "))

parms = EncryptionParameters()
parms.set_poly_modulus("1x^32768 + 1")
parms.set_coeff_modulus(seal.coeff_modulus_128(16384))
parms.set_plain_modulus(1 << 30)
context = SEALContext(parms)

encoderF = FractionalEncoder(context.plain_modulus(), context.poly_modulus(), 34, 30, 2) 
keygen = KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()

ev_keys = EvaluationKeys()
keygen.generate_evaluation_keys(15, ev_keys)

encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)
"""
try:
	t=encoderF.encode(3)
	print(t)
	t=encoderF.encode(5**13)
	print(t)
except:
	pass
"""
for N in range(5,11):
	Q=[]
	for i in range(N):
		q=[]
		for j in range(N):
			q+= [random.random()]
		Q.append(q)

	X= np.asarray(Q)
	X= X.reshape(N,N)
	X= (X+ X.T)/2
	print("Matrix to be inversed is of size "+str(N)+ " -")
	print(X)
		
	print(np.linalg.det(X))
	print("Inverse by Numpy:")
	print(np.linalg.inv(X))

	#print("\nMain program: ")
	t= time.time()
	X= encrypt_matrix(X)
	t1= time.time()
	print("[=] Time taken to complete encrypting: ", t1-t)
	X_inv=inverseMatrix(X)
	print("[=] Time taken to complete Homomorphic: ", time.time()-t1)
	decrypt_matrix(X_inv)
	print()
	gc.collect()
