import random
import numpy
import math
import scipy
from scipy.stats import norm

n = 10000 # number of individuals
m = 1000  # number of SNPs
k = 15    # Number of covariates

S=[]
for i in range (n):
	s=[]
	for j in range(m):
		s.append(2*random.random())
	S.append(s)

y=numpy.random.normal(0,1,n)	# nx1 matrix

X=[]	#nXk matrix
for i in range(n):
	x=[1]
	for j in range(k):
		x.append(numpy.random.normal(0,1))
	X.append(x)
tX=numpy.transpose(X)

U1= numpy.matmul(tX, y)
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
print(p)
logp= -numpy.log10(p)
logp.tolist()
print(logp)