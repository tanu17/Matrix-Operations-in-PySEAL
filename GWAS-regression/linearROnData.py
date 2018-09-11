# linear regression without HE
import random
import numpy
import math
import scipy
from scipy.stats import norm

def normalize(M):
	# normalizes raw data on user end
	for i in range(len(M)):
		maxR=max(M[i])
		minR=min(M[i])
		for j in range(len(M[i])):
			M[i][j]= (M[i][j] - minR) / float(maxR-minR)
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


Tcov=[list(tup) for tup in zip(*cov_new)]

y= Tcov[0]
rawX0= Tcov[1:4]


rawX0 = normalize(rawX0)

print(rawX0)

tX=[[1]*245]+ rawX0
X=[list(tup) for tup in zip(*tX)]


# dimension of X ->  n (number of individuals) rows and 1+k (1+ number of covariates) cols
# dimension of y -> vector of length n (number of individuals)
# dimension of S ->  n (number of individuals) rows and m (number of SNPs)


n=len(S) # n=245
m= len(S[0])# m=10643
k= len(X[0]) # k =3

y=numpy.asarray(y)

U1= numpy.matmul(tX,y)
print("\nU1:\n",U1)
# dimension of U1 ->  vector of length k+1 (1+ number of covariates)

cross_X= numpy.matmul(tX,X)
print("\ncross_X:\n",cross_X)
# dimension of cross_X ->  1+k rows and 1+k cols

print("\nSize to inverse: ", len(cross_X))
X_Str=numpy.linalg.inv(cross_X)
print("\nX*\n",X_Str)

U2=numpy.matmul(X_Str, U1)
print("\nU2:\n",U2)
# dimension of U2 ->  vector of length k+1 (1+ number of covariates)
#U2.tolist()

y_str= numpy.subtract(y,numpy.matmul(X,U2))
#y_str.tolist()

U3= numpy.matmul(tX,S)
print("\nU3:\n",U3)
# dimension of U3 -> 1+k rows and m (number of SNPs)

U4= numpy.matmul(X_Str, U3)
# dimension of U4 -> 1+k rows and m (number of SNPs)
print("\nU4:\n",U4)

S_str=numpy.subtract(S,numpy.matmul(X,U4))
# dimension of S_star -> n (number of individuals) rows and m (number of SNPs)

S_str2=numpy.square(S_str).sum(axis=0)
# dimension of S_star2 -> vector of length m (number of SNPs)
print("\nS_star2\n:",S_str2)


tY_str=numpy.transpose(y_str)
b_temp=numpy.matmul(tY_str, S_str)
b=numpy.divide(b_temp, S_str2)
# dimension of b -> vector of length m (number of SNPs)
print("\nb:\n",b)

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
print("\n"+"_"*30 + "\nlogp:\n")
print(logp)
