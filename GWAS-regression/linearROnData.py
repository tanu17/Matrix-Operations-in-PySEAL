# linear regression without HE
import random
import numpy
import math
import scipy
from scipy.stats import norm

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
		#print(maxR)
		#print((minR))
		#print(row)
		for i in range(len(row)):
			row[i]= (row[i] - minR) / avg
		#print(row)
	return(M)

snp = open("C:/Users/User/Desktop/GWAS analysis/analysis1/vcf/snpMat.txt","r+")
S=[]
for row in snp.readlines():
	S.append(row.strip().split())
S=S[1:]

S = numpy.array(S).astype(numpy.float)


covariate= open("C:/Users/User/Desktop/GWAS analysis/analysis1/covariates.csv")
cov=[]
for row in covariate.readlines():
	cov.append(row.strip().split(","))
Tcov=[list(tup) for tup in zip(*cov)]

y= Tcov[1][1:]
rawX0= Tcov[2:5]

for i in range(len(rawX0)):
	rawX0[i]=rawX0[i][1:]
tX=[[1]*245]+ rawX0

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
