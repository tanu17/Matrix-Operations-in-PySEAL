import random
import numpy
import time,os,sys
import seal
import pickle
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

def create_EncodedMatrix(M):
	EncodedPath = dir_path+'/encodedFiles'
	if not os.path.isdir(path):
		try: 
		    os.makedirs(path)
		except OSError:
		    pass
	else:
		row=len(M)
		col=len(M[0])
		X=[]
		for i in range(row):
			x=[]
			for j in range(col):
				x.append(encoderF.encode(M[i][j]))
			X.append(x)
		print("-"*20+" Matrix encoded "+ "-"*20)
		pickle.dump( X, open( dir_path+"/encodedFiles"+"/encodedS.matrix", "wb" ) )	
		thefile = open(dir_path+"/encodedFiles"'encS.txt', 'w')
		for item in X:
		  thefile.write("%s\n" % item)
		del(X)
		print("Encoded matrix files created")
		

parms = EncryptionParameters()
parms.set_poly_modulus("1x^8192 + 1")
parms.set_coeff_modulus(seal.coeff_modulus_128(8192))
parms.set_plain_modulus(1 << 21)
context = SEALContext(parms)

encoderF = FractionalEncoder(context.plain_modulus(), context.poly_modulus(), 30, 34, 3)
encoderVariabeles={"plain_modulus":1 << 21, "ploy_modulus":"1x^8192 + 1", "encoder": [30,34,3] }

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

S_encoded=create_EncodedMatrix(S)
del(S)
gc.collect()
print("-"*20+"matrix has been encoded"+ "-"*20)


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
