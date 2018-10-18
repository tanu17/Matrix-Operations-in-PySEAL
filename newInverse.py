import numpy 
import itertools
import random,math
import seal
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


def parallel_encryption(element):
	temp=Ciphertext()
	encryptor.encrypt(encoderF.encode(element), temp)
	return(temp)

def encrypting_Matrix(M):
	enc_M=[]
	Enc_pool = multiprocessing.Pool(processes=num_cores)

	# M is vector
	if ( type(M[0]) != list ):
		enc_M= Enc_pool.map(parallel_encryption, M)

	else:
		for i in range(len(M)):
			enc_M.append(Enc_pool.map(parallel_encryption, M[i]))
	del(M)
	Enc_pool.close()
	Enc_pool.join()
	return(enc_M)


def dot_vector(row,col):
	D=[]
	for i in range(len(row)):
		temp=Ciphertext()
		D.append(matrixOperationHE.multiplication(row[i],col[i]))
	evaluator.add_many(D,temp)	
	return(temp)

def multiplication(element1,element2):
	# have to create new ciphertext object as row X column multiplication of matrix enforces no change in matrix elements
	temp=Ciphertext()
	evaluator.multiply(element1, element2, temp)
	#evaluator.relinearize(element1, ev_keys)
	return (temp)


def matrixMultiply(T,K,symmetric=0):
	Mul_pool= multiprocessing.Pool(processes=num_cores)
	P=[]

	if (symmetric):
		P=[[None]*n]*
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

def print_plain(D):
    # function to print out all elements in a matrix/vector
    D_new= decrypt_matrix(D)
    for row in D_new:
    	print(row)
    del(D_new)


def hadamardProduct_trace(X,Y):
	tr=Ciphertext()
	trace_Pool= multiprocessing.Pool(processes=num_cores)
	P= trace_Pool.starmap(multiplication, zip(numpy.hstack(X),numpy.hstack(Y)))
	evaluator.add_many(P,tr)
	trace_Pool.close()
	return(tr)

def coefficientPolyCreate(trace_vector):
	coeff=[Ciphertext(trace_vector[0])]
	evaluator.negate(coeff[0])
	for i in range(1,N):
		c_new= Ciphertext()
		Q= [Ciphertext(trace_vector[i])]
		for j in range(i):
			temp= Ciphertext()
			evaluator.multiply(coeff[j], trace_vector[i-j-1], temp)
			Q.append(tc)
		evaluator.add_many(Q, c_new)
		frac= encoderF.encode(-1/(i+1))
		evaluator.multiply_plain(c_new, frac)
		coeff.append(c_new)
	c0=Ciphertext()
	encryptor.encrypt(encoderF.encode(1),c0)
	coeff=[c0]+coeff
	return(coeff)

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
	for i in range(1,math.ceil(len(M)/2)):
		Power_vector_Half.append(matrixMultiply(M,Power_vector_Half[i-1]))
	Power_vector_Half= [iden_matrix(N)]+ Power_vector_Half
	return(Power_vector_Half)


def parallel_plainMultiplication(element,D):
	# have to create new ciphertext object as row X column multiplication of matrix enforces no change in matrix elements
	evaluator.multiply_plain(element, D)
	return(element)

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
	return(M_inverse)

def SymetricMatrixCompletion(M):
	n= len(M)
	N=n
	for rowIndex in range(n):
		if len(M[rowIndex])<n:
			M[rowIndex]+=[None]*(n-len(M[rowIndex]))
	for rowIndex in range(n):
		for colIndex in range(rowIndex+1,n):
			if M[rowIndex][colIndex]==None:
				M[rowIndex][colIndex]=Ciphertext(M[colIndex][rowIndex])

	print_plain(M)



if __name__ == '__main__':

	multiprocessing.freeze_support()

	########################## paramaters required #################################

	parms = EncryptionParameters()
	parms.set_poly_modulus("1x^16384 + 1")
	parms.set_coeff_modulus(seal.coeff_modulus_128(8192))
	parms.set_plain_modulus(1 << 25)
	context = SEALContext(parms)

	encoderF = FractionalEncoder(context.plain_modulus(), context.poly_modulus(), 34, 30, 3) 
	keygen = KeyGenerator(context)
	public_key = keygen.public_key()
	secret_key = keygen.secret_key()

	encryptor = Encryptor(context, public_key)
	evaluator = Evaluator(context)
	decryptor = Decryptor(context, secret_key)

	num_cores = multiprocessing.cpu_count() -1

	N=4
	b = numpy.random.random_integers(1,10,size=(N,N))
	X = (b + b.T)/2
	print("\nX:")
	print(X)
	print(numpy.linalg.det(X))
	print("Inverse by Numpy:")
	print(numpy.linalg.inv(X))
	print("\nMain program: \n")
	X= encrypting_Matrix(X)
	X_inv=inverseMatrix(X)
	SymetricMatrixCompletion(X_inv)