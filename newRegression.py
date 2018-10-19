#!/usr/bin/env python3
#from functools import partial
import random
import math
import os
import numpy
import time
import itertools
import seal
import gc
import scipy
from scipy.stats import norm
import multiprocessing 
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


def normalize(M):
	# normalizes raw data on user end
	for i in range(len(M)):
		maxR=max(M[i])
		minR=min(M[i])
		for j in range(len(M[i])):
			M[i][j]= (M[i][j] - minR) / float(maxR-minR)
	return(M)

def parallel_plainMultiplication(element,D):
	# have to create new ciphertext object as row X column multiplication of matrix enforces no change in matrix elements
	evaluator.multiply_plain(element, D)
	return(element)

def parallel_encryption(element):
	temp=Ciphertext()
	encryptor.encrypt(encoderF.encode(element), temp)
	return(temp)

def parallel_decryption(element):
	p=Plaintext()
	decryptor.decrypt(element, p)
	temp= encoderF.decode(p)
	return(temp)

def decrypt_matrix(M):
	M_dec= []
	dec_Pool= multiprocessing.Pool(processes=num_cores)

	# M is vector
	if ( type(M[0]) != list ):
		M_dec= dec_Pool.map(parallel_decryption, M)
	else:
		for i in range(len(M)):
			M_dec.append(dec_Pool.map(parallel_decryption, M[i]))
	dec_Pool.close()
	dec_Pool.join()
	return(M_dec)

def encrypting_Matrix(M):
	enc_M=[]
	Enc_pool = multiprocessing.Pool(processes=num_cores)
	# M is vector
	if ( type(M[0]) != list and type(M[0])!=numpy.ndarray):
		enc_M= Enc_pool.map(parallel_encryption, M)

	else:
		for i in range(len(M)):
			enc_M.append(Enc_pool.map(parallel_encryption, M[i]))
	del(M)
	Enc_pool.close()
	Enc_pool.join()
	return(enc_M)

def parallelSquare(element):
	temp=Ciphertext()
	evaluator.square(element,temp)
	return(temp)

def colSquare_Sum(M):
	tM = [list(tup) for tup in zip(*M)]
	# last step for finding p values, hance can delete the original matrix
	del(M)
	X=[]
	rowM=len(tM)
	for i in range(rowM):
		x=Ciphertext()
		for j in range(len(tM[i])):
			#y=Ciphertext()
			evaluator.square(tM[i][j])
			#~~~~~~~~~~~~~ can have need to relinearize or changing parameter ~~~~~~~~~~

		evaluator.add_many(tM[i],x)
		#del(y)
		X.append(x)
	del(tM)
	return(X)

def dot_vector(row,col):
	D=[]
	for i in range(len(row)):
		temp=Ciphertext()
		D.append(multiplication(row[i],col[i]))
	evaluator.add_many(D,temp)	
	return(temp)

def subtract(element1,element2):
	temp=Ciphertext()
	evaluator.negate(element2)
	evaluator.add(element1,element2,temp)
	return(temp)

def multiplication(element1,element2):
	# have to create new ciphertext object as row X column multiplication of matrix enforces no change in matrix elements
	temp=Ciphertext()
	evaluator.multiply(element1, element2, temp)
	#evaluator.relinearize(element1, ev_keys)
	return (temp)

def print_plain(D):
    # function to print out all elements in a matrix/vector
    D_new= decrypt_matrix(D)
    for row in D_new:
    	print(row)
    del(D_new)

def subtractMatrix(T,K):
	Sub_pool = multiprocessing.Pool(processes=num_cores)
	X=[]
	if ( type(T[0]) != list):
		X=Sub_pool.starmap(matrixOperationHE.subtract, zip(T,K))
	else:
		for i in range(len(T)):
			X.append(Sub_pool.starmap(matrixOperationHE.subtract,zip(T[i],K[i])))
	Sub_pool.close()
	#Sub_pool.join()
	return(X)

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


def matrixMultiply(T,K,symmetric=0):
	Mul_pool= multiprocessing.Pool(processes=num_cores)
	P=[]

	if (symmetric):
		P=[[None]*n]
		dim= len(T)
		tK=[list(tup) for tup in zip(*K)]
		for i in range(n):
			for j in range(i,n):
				addVector= Mul_pool.starmap(multiplication, zip(T[i]),tK[j])
				element= Ciphertext()
				evaluator.add_many(addVector,element)
				P[i][j]=element
				if i!=j:
					P[j][i]=Ciphertext(element)

	else:
		P=[]

		#K is vector
		if ( type(K[0]) != list ):
			P= Mul_pool.starmap(dot_vector, zip(T, itertools.repeat(K)))

		else:
			tK=[list(tup) for tup in zip(*K)]

			if (len(T)<=len(T[0]) ):
				for i in range(len(T)):
					row_p=[]
					for j in range(len(tK)):
						D=Ciphertext()
						evaluator.add_many( Mul_pool.starmap(multiplication, zip(T[i], tK[j])) , D )
						row_p.append(D)
					P.append( row_p)

			else:
				for i in range(len(tK)):
					P.append(Mul_pool.starmap(dot_vector, zip(itertools.repeat(tK[i]),T)))
				P= [list(tup) for tup in zip(*P)]
			del(tK)

	Mul_pool.close()		
	return(P)


def hadamardProduct_trace(X,Y):
	tr=Ciphertext()
	trace_Pool= multiprocessing.Pool(processes=num_cores)
	P= trace_Pool.starmap(multiplication, zip(numpy.hstack(X),numpy.hstack(Y)))
	evaluator.add_many(P,tr)
	trace_Pool.close()
	return(tr)

def coefficientPolyCreate(trace_vector):
	N= len(trace_vector)
	coeff=[Ciphertext(trace_vector[0])]
	evaluator.negate(coeff[0])
	for i in range(1,N):
		c_new= Ciphertext()
		Q= [Ciphertext(trace_vector[i])]
		for j in range(i):
			temp= Ciphertext()
			evaluator.multiply(coeff[j], trace_vector[i-j-1], temp)
			Q.append(temp)
		evaluator.add_many(Q, c_new)
		frac= encoderF.encode(-1/(i+1))
		evaluator.multiply_plain(c_new, frac)
		coeff.append(c_new)
	c0=Ciphertext()
	encryptor.encrypt(encoderF.encode(1),c0)
	coeff=[c0]+coeff
	return(coeff)


def trace(M):
		t=Ciphertext(M[0][0])
		for i in range(1,len(M)):
			evaluator.add(t,M[i][i])
		return (t)


def TraceCalculation(Power_vector_Half):
	traceVec=[]
	tempVec=[]
	for i in range(1,len(Power_vector_Half)):
		traceVec.append(trace(Power_vector_Half[i]))

	N= len(Power_vector_Half[0])

	if (N%2 ==0):
		for i in range(N//4 + 1, int(N/2) +1):
			if(2*i-1 > len(traceVec)):
				traceVec.append(hadamardProduct_trace(Power_vector_Half[i],Power_vector_Half[i-1]))
			traceVec.append(hadamardProduct_trace(Power_vector_Half[i],Power_vector_Half[i]))
	else:
		#print("else")
		for i in range(N//4 + 1, N//2 +2):
			if (i> N//4 + 1):
				#print(i,2*i-1)
				traceVec.append(hadamardProduct_trace(Power_vector_Half[i],Power_vector_Half[i-1]))
			if (N> 2*i and 2*i>N//2 +1):
				#print(i,2*i)
				traceVec.append(hadamardProduct_trace(Power_vector_Half[i],Power_vector_Half[i]))

	tempVec.reverse()
	traceVec+=tempVec
	return(traceVec)


def Power_vector_HalfCalculation(M):
	# Power_vector_Half= [ I, M, M^2, M^3,....M^[(n+1)/2] ]
	Power_vector_Half= [M]
	N= len(M)
	for i in range(1,math.ceil(len(M)/2)):
		Power_vector_Half.append(matrixMultiply(M,Power_vector_Half[i-1]))
	Power_vector_Half= [iden_matrix(N)]+ Power_vector_Half
	return(Power_vector_Half)


def multiplyDeterminant(M, determinant):
	p=Plaintext()
	plainMul_pool = multiprocessing.Pool(processes=num_cores)
	# need to send user D so that user can send back -1/D either in encrypted form or decrypted form
	decryptor.decrypt(determinant, p)
	d= (-1/encoderF.decode(p))
	delta=encoderF.encode(d)
	del(p)
	X=[]
	for i in range(len(M)):
		X.append(plainMul_pool.starmap(parallel_plainMultiplication, zip(M[i],itertools.repeat(delta))))
	plainMul_pool.close()
	return(X)


def inverseMatrix(M):

	Power_vector_Half= Power_vector_HalfCalculation(M)
	trace_vector= TraceCalculation(Power_vector_Half)
	coefficientPoly= coefficientPolyCreate(trace_vector) 

	M_inverse=[]
	#print(coefficientPoly)
	determinant= coefficientPoly.pop()
	n= len(M)

	# x= [0]*n-i-1 + [1] + [0]*i
	for i in range(n-1, -1, -1):

		powerMatrix_X=[]
		for j in range(len(Power_vector_Half)):
			powerMatrix_X.append(Power_vector_Half[j][i])
		# multiplies x with powers I, A, A^2 ... A^( [n/2  + 0.5] )

		for j in range(len(Power_vector_Half),n):
			# to avoid budget of only one matrix to go down, we randomly choose vector. 
			# differece will be noticable when matrix is large, here n is 4, so wont matter much here
			partition_1= random.randint(n//4 + 1,n//2)
			if (j-partition_1>=len(Power_vector_Half)):
				partition_1=len(Power_vector_Half)-1
			partition_2= j - partition_1
			muliplier1= Power_vector_Half[partition_1][:i+1]
			muliplier2= Power_vector_Half[partition_2][i]
			Z= matrixMultiply(muliplier1,muliplier2)
			powerMatrix_X.append( Z )
		# powerMatrix_X is powerMatrix multiplied by x vector

		for j in range(len(powerMatrix_X)):
			powerMatrix_X[j]=powerMatrix_X[j][:i+1]
			for l in range(len(powerMatrix_X[j])):
				evaluator.multiply(powerMatrix_X[j][l],coefficientPoly[n-1-j])

		tInverseRow=[list(tup) for tup in zip(*powerMatrix_X)]
		InverseRow=[]
		for z in range(len(tInverseRow)):
			temp=Ciphertext()
			evaluator.add_many(tInverseRow[z],temp)
			InverseRow.append(temp)

		M_inverse.append(InverseRow)

	M_inverse=multiplyDeterminant(M_inverse, determinant)
	M_inverse.reverse()
	M_inverse=SymetricMatrixCompletion(M_inverse)

def SymetricMatrixCompletion(M):
	n= len(M)
	for rowIndex in range(n):
		if len(M[rowIndex])<n:
			M[rowIndex]+=[None]*(n-len(M[rowIndex]))
	for rowIndex in range(n):
		for colIndex in range(rowIndex+1,n):
			if M[rowIndex][colIndex]==None:
				M[rowIndex][colIndex]=Ciphertext(M[colIndex][rowIndex])
	return(M)



if __name__ == '__main__':

	multiprocessing.freeze_support()

	########################## paramaters required #################################

	parms = EncryptionParameters()
	parms.set_poly_modulus("1x^16384 + 1")
	parms.set_coeff_modulus(seal.coeff_modulus_128(16384))
	parms.set_plain_modulus(1 << 34)
	context = SEALContext(parms)

	encoderF = FractionalEncoder(context.plain_modulus(), context.poly_modulus(), 34, 30, 3) 
	keygen = KeyGenerator(context)
	public_key = keygen.public_key()
	secret_key = keygen.secret_key()

	encryptor = Encryptor(context, public_key)
	evaluator = Evaluator(context)
	decryptor = Decryptor(context, secret_key)

	num_cores = multiprocessing.cpu_count() -1


	########################## processing main matrix ################################

	t1 = time.time()
	dir_path=os.path.dirname(os.path.realpath(__file__))

	snp = open(dir_path+"/snpMat.txt","r+")
	S=[]
	for row in snp.readlines():
		S.append(row.strip().split())
	S=S[1:]
	S = numpy.array(S).astype(numpy.float)
	S.tolist()
	n= len(S) # n=245
	m= len(S[0])# m=1064

	gc.collect()

	################ processing covariate matrix and derivatives ######################
	

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
				cov_sum[j-2][1]+=1.0

	for i in range(len(cov_sum)):
		cov_sum[i]=cov_sum[i][0]/cov_sum[i][1]
	cov_new=[]
	for i in range(len(cov)):
		cov_new_row=[]
		for j in range(1,5):
			if cov[i][j] =="NA":
				cov_new_row.append(cov_sum[j-2])
			else:
				cov_new_row.append(int(cov[i][j]))
		cov_new.append(cov_new_row)

	# splitting off of covariate matrix
	Tcov= [list(tup) for tup in zip(*cov_new)]
	del(cov_new)
	gc.collect()
	y= Tcov[0]
	rawX0= Tcov[1:4]

	rawX0=normalize(rawX0)
	# have to find a way to make normalize an encrytped function

	# Test with a few SNPs of a few people
	nSNP = 6
	nPerson = 50

	S = S[0:nPerson, 0:nSNP]
	y = y[0:nPerson]
	rawX0 = [row[0:nPerson] for row in rawX0]
	#print(S)
	#print(rawX0)

	###################### encrypting tX and y #####################################
	tX=[[1]*len(rawX0[0])] + rawX0
	print("[+] Starting enrypting matrices")
	row_tX=len(tX) #row_tX= 3
	col_tX=len(tX[0]) #col_tX= 245

	# encrypting matrix tX
	tX_encrypted= encrypting_Matrix(tX)
	try:
		del(rawX0)
		del(tX)
	except:
		pass
	gc.collect()

	X=[list(tup) for tup in zip(*tX_encrypted)]
	print("[+] Encrypted X")
	
	
	#encrypting y
	y_encrypted= encrypting_Matrix(y)
	try:
		del(y)
	except:
		pass
	print("[+] Encrypted y")
	
	########################### encrypting S #######################################

	tS=[list(tup) for tup in zip(*S)]
	#S_encRECON=[]
	#S_enc=[]

	#for i in range(0,,2):
		#a= matrixEncryptRows(tS[i:i+2])
		#del(a)
	S_enc=encrypting_Matrix(tS)
	#del(a)
	print("[+] Matrix S encrytped")
	S_enc=[list(tup) for tup in zip(*S_enc)]
	
	########################## linear regression Pt. 1 ##############################

	print('Time cost: {} seconds'.format(time.time()-t1))
	gc.collect()
	t2 = time.time()

	print("\n[+] Proceding to homomorphic functions")

	k= len(X[0]) # k= 3
	
	cross_X= matrixMultiply(tX_encrypted,X)
	print("Noise budget of cross_X[1][1]:"+ str(decryptor.invariant_noise_budget(cross_X[1][1])))
	print("[+] Calculated cross_X")
	print_plain(cross_X)
	# dimension of cross_X ->  1+k rows and 1+k cols

	#U1= encrypting_Matrix([ 108.0 ,42.37975927,44.43704984,52.77309281])

	#cross_X= encrypting_Matrix( [[ 245.0,91.26565954,95.24248535,118.42642904],[  91.26565954 ,39.67640403 ,35.41864926,43.98636322] ,[  95.24248535 ,35.41864926 ,41.46235818 ,48.28531555],[ 118.42642904,43.98636322,48.28531555 ,61.48756469]])

	print("{=} Size to inverse: ", len(cross_X))
	X_Star= inverseMatrix(cross_X)
	#X_star=multiplyDeterminant(X_Star, determinant_X_star)
	print("Noise budget of X_Star[1][1]:"+ str(decryptor.invariant_noise_budget(X_Star[1][1])))
	print_plain(X_Star)
	print("[+] Calculated inverse")

	gc.collect()

	projectionTemp= matrixOperationHE.matrixMultiply(X, X_Star)
	print("\nNoise budget of projectionTemp[1][1]:"+ str(decryptor.invariant_noise_budget(projectionTemp[1][1])))
	print("[+] Calculated projectionTemp")
	projectionMatrix= matrixOperationHE.matrixMultiply(projectionTemp, tX_encrypted)
	print("\nNoise budget of projectionMatrix[1][1]:"+ str(decryptor.invariant_noise_budget(projectionMatrix[1][1])))
	print_plain(projectionMatrix)
	print("[+] Calculated projectionMatrix")

	y_temp= matrixOperationHE.matrixMultiply(projectionMatrix, y_encrypted)
	print("\nNoise budget of y_temp[1][1]:"+ str(decryptor.invariant_noise_budget(y_temp[1])))
	print("[+] Calculated y_temp")

	S_temp= matrixOperationHE.matrixMultiply(projectionMatrix, S_enc)
	print("\nNoise budget of S_temp[1][1]:"+ str(decryptor.invariant_noise_budget(S_temp[1][1])))
	print("[+] Calculated S_temp")

	S_star= matrixOperationHE.subtractMatrix(S_enc, S_temp)
	print("\nNoise budget of S_star[1][1]:"+ str(decryptor.invariant_noise_budget(S_star[1][1])))
	print("[+] Calculated S_star")


	y_star=matrixOperations.subtractMatrix(y_encrypted,y_temp)
	print("\nNoise budget of y_star[1]:"+ str(decryptor.invariant_noise_budget(y_star[1])))
	print("[+] Calculated y_star")

	b_temp= matrixOperations.matMultiply(y_star,S_star)
	S_star2=matrixOperations.colSquare_Sum(S_star)

	print("[=] Finished with homomorphic functions")
	print('Time cost: {} seconds'.format(time.time()-t2))

	t3 = time.time()

	########################## linear regression Pt. 2 ##############################
	######## after returning some matrix to decrypt and to evaluate by user #########

	gc.collect()
	print("\n[+] User-end calculations started")

	b_temp_dec= numpy.asarray(decrypt_matrix(b_temp))
	S_star2_dec= numpy.asarray(decrypt_matrix(S_star2))
	y_str= numpy.asarray(decrypt_matrix(y_star))

	y_star2_dec= numpy.square(y_str)


	try:
		# S-enc should be deleted first
		del(S_enc)
		del(S_star_temp)
	except:
		pass
	try:
		del(b_temp)
		del(S_star2)
		del(y_encrypted)
	except:
		pass

	b=numpy.divide(b_temp_dec, S_star2_dec)
	print("\nb:\n",b)
	# dimension of b -> vector of length m (number of SNPs)

	b2= numpy.square(b)

	sig = numpy.subtract(numpy.sum(y_star2_dec),numpy.multiply(b2,S_star2_dec)) / (n-k-2)

	print(numpy.shape(sig))
	print(numpy.shape(b2))
	print(numpy.shape(S_star2_dec))

	err= numpy.sqrt(sig*(1/S_star2_dec))

	f=numpy.divide(b,err)
	f=-abs(f)
	p=[]
	for x in f:
		p.append( 1 - (norm(0, 1).cdf(x)) )
	logp= -numpy.log10(p)
	logp.tolist()

	print("\n[+] P-Values: ")
	print("_"*30 + "\nlogp:\n")
	print(logp)