import numpy
import random,math

def hadamardProduct_trace(X,Y):
	tr=numpy.dot(numpy.hstack(X),numpy.hstack(Y))
	return(tr)

def coefficientPolyCreate(trace_vector):
	coeff= [-trace_vector[0]]
	for i in range(1,N):
		c_new= trace_vector[i]
		for j in range(i):
			temp= coeff[j]*trace_vector[i-j-1]
			c_new += temp
		frac= -1/(i+1)
		c_new *= frac
		coeff.append(c_new)
	c0=1
	coeff=[c0]+coeff
	# coeff= [c0,c1,c2,...cn]
	return(coeff)

def iden_matrix(n):
    m=[[0 for x in range(n)] for y in range(n)]
    for i in range(0,n):
        m[i][i] = 1
    return m

def trace(M):
	t=numpy.trace(M)
	return(t)

def TraceCalculation(Power_vector_Half):
	traceVec=[]
	tempVec=[]
	n= int(N)
	for i in range(1,len(Power_vector_Half)):
		traceVec.append(trace(Power_vector_Half[i]))
	if (n%2 ==0):
		for i in range(n//4 + 1, int(n/2) +1):
			traceVec.append(hadamardProduct_trace(Power_vector_Half[i],Power_vector_Half[i-1]))
			traceVec.append(hadamardProduct_trace(Power_vector_Half[i],Power_vector_Half[i]))
	else:
		for i in range(n//4 + 1, n//2 +2):
			if (i> n//4 + 1):
				traceVec.append(hadamardProduct_trace(Power_vector_Half[i],Power_vector_Half[i-1]))
			if (n> 2*i and 2*i> n//2 +1):
				traceVec.append(hadamardProduct_trace(Power_vector_Half[i],Power_vector_Half[i]))

	tempVec.sort()
	# traceVec= [traceA, traceA^2..., traceA^n]
	traceVec+=tempVec
	"""
	pow2=numpy.matmul(Power_vector_Half[1], Power_vector_Half[1])
	pow3=numpy.matmul(pow2, Power_vector_Half[1])
	pow4=numpy.matmul(pow3, Power_vector_Half[1])
	pow5=numpy.matmul(pow4, Power_vector_Half[1])
	pow6=numpy.matmul(pow5 , Power_vector_Half[1])
	pow7=numpy.matmul(pow6, Power_vector_Half[1])
	print([numpy.trace(Power_vector_Half[1]),numpy.trace(pow2),numpy.trace(pow3),numpy.trace(pow4),numpy.trace(pow5),numpy.trace(pow6),numpy.trace(pow7)][:N])
	"""
	return(traceVec)


def Power_vector_HalfCalculation(M):
	Power_vector_Half= [M]
	for i in range(1,math.ceil(len(M)/2)):
		Power_vector_Half.append(numpy.matmul(M,Power_vector_Half[i-1]))
	# Power_vector_Half= [ I, M, M^2, M^3,....M^[(n+1)/2] ]
	Power_vector_Half= [iden_matrix(N)]+ Power_vector_Half
	return(Power_vector_Half)


def inverseMatrix(M):

	Power_vector_Half= Power_vector_HalfCalculation(M)
	trace_vector= TraceCalculation(Power_vector_Half)
	coefficientPoly= coefficientPolyCreate(trace_vector) 

	M_inverse=[]
	print(coefficientPoly)
	deteminant= coefficientPoly.pop()
	n= len(coefficientPoly)
	print()

	for i in range(n-1, -1, -1):
		# x= [0]*n-i-1 + [1] + [0]*i
		powerMatrix_X=[]
		for j in range(len(Power_vector_Half)):
			powerMatrix_X.append(Power_vector_Half[j][i])
		# multiplies x with powers I, A, A^2 ... A^( [n/2  + 0.5] )

		for j in range(len(Power_vector_Half),n):
			# to avoid budget of only one matrix to go down, we randomly choose vector. 
			# differece will be noticable when matrix is large, here n is 4, so wont matter much here
			#print(i,j)
			partition_1= random.randint(n//4+1,n//2)
			partition_2= j - partition_1
			#print(i,j, partition_1, partition_2)
			muliplier1= Power_vector_Half[partition_2][:i+1]
			muliplier2= powerMatrix_X[partition_2]
			powerMatrix_X.append( numpy.matmul(muliplier1,muliplier2) )

		# powerMatrix_X is powerMatrix multiplied by x vector
		for j in range(len(powerMatrix_X)):
			for l in range(len(powerMatrix_X[j])):
				powerMatrix_X[j][l]=powerMatrix_X[j][l]*float(coefficientPoly[n-1-j])
		print()

		tInverseRow=[list(tup) for tup in zip(*powerMatrix_X)]
		InverseRow=[]
		print(i,tInverseRow)

		for x in tInverseRow:
			InverseRow.append(sum(x))
		print(InverseRow)
		M_inverse.append(InverseRow)

	print(deteminant)
	for x in range(len(M_inverse)):
		for y in range(len(M_inverse[x])):
			M_inverse[x][y]=M_inverse[x][y]/(-deteminant)
	M_inverse.reverse()
	for row in M_inverse:
		print(row)


#N= int(inumpyut("Enter dimensions: "))
N=5
b = numpy.random.random_integers(0,10,size=(N,N))
X = (b + b.T)/2
print(X)
print(numpy.linalg.det(X))
print(numpy.linalg.inv(X))
print()
print("\nMain program: \n")
inverseMatrix(X)
