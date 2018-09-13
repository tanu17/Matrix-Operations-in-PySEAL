#!/usr/bin/env python3
from functools import partial
import random
import math
import os
import numpy
import time
import itertools
import seal
import gc
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


########################## matrixOperations ######################################

class matrixOperations:

    @staticmethod
    def parallel_Multiplication(element1,element2):
        # have to create new ciphertext object as row X column multiplication of matrix enforces no change in matrix elements
        temp=Ciphertext()
        evaluator.multiply(element1, element2, temp)
        return (temp)

    @staticmethod
    def dot_vector(row,col):
        # returns dot vector between two vectors
        pool = multiprocessing.Pool(processes=num_cores)
        D = pool.starmap(matrixOperations.parallel_Multiplication, zip(row, col))
        empty_ctext=Ciphertext()
        evaluator.add_many(D,empty_ctext)
        del(D)
        pool.close()
        return(empty_ctext)


    @staticmethod
    def matMultiply(T,K):
    # multipliess two matrix and returns a new matrix as result
        X=[]

        if ( type(K[0]) != list ):
            # K is a vector 
            for i in range(len(T)):
                X.append(matrixOperations.dot_vector(T[i], K))

        elif ( type(T[0]) != list ):
            # T is a vector instead of matrix
            tK=[list(tup) for tup in zip(*K)]
            del(K)

            for i in range(len(tK)):
                X.append( matrixOperations.dot_vector(tK[i], T) )

        else:
            tK=[list(tup) for tup in zip(*K)]

            for i in range(len(T)):
                row_X=[]
                for j in range(len(tK)):
                    row_X.append(matrixOperations.dot_vector(T[i], tK[j]))
                X.append( row_X )
            del(tK)

        return(X)


    @staticmethod
    def multScaler(s, L):
    # multiplies a matrix L with a scaler s, changes the same matrix
        for x in L:
            for y in x:
                evaluator.multiply(y,s)


    @staticmethod
    def trace(M):
    # calculates trace of a matrix 
        t=Ciphertext(M[0][0])
        for i in range(1,len(M)):
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
        # subtract the first matrix bt second matrix, the result are overridden in the first matrix itself
        for i in range(len(T)):
            if ( type(T[0]) != list):
                evaluator.sub(T[i], K[i])
            else:
                for j in range(len(T[0])):
                    evaluator.sub(T[i][j], K[i][j])


    @staticmethod
    def colSquare_Sum(M):
        # returns sums of squares of each element in a column of a matrix. Returns a vector with length ewual to number of columns in a matrix
        tM = [list(tup) for tup in zip(*M)]
        # last step for finding p values, hance can delete the original matrix
        del(M)
        X=[] 
        rowM=len(tM)
        for i in range(rowM):
            x=Ciphertext()
            encryptor.encrypt(encoderF.encode(0),x)
            for j in range(len(tM[i])):
                y=Ciphertext()
                evaluator.square(tM[i][j])
#~~~~~~~~~~~~~ can have need to relinearize or changing parameter ~~~~~~~~~~
                evaluator.add(x,tM[i][j])
            del(y)
            X.append(x)
        return(X)


    @staticmethod
    def inverseMatrix(K):
        # function for finding inverse of the matrix via Cayley-Hamilton theorem 
        # http://scipp.ucsc.edu/~haber/ph116A/charpoly_11.pdf
        n=len(K)
        matrixPower_vector=[K]
        trace_vector=[matrixOperations.trace(K)]

        for i in range(1,n):
#~~~~~~~~~~~~~ can have need to relinearize or changing parameter ~~~~~~~~~~
            matrixPower_vector+=[matrixOperations.matMultiply(K, matrixPower_vector[i-1])]
            trace_vector+=[matrixOperations.trace(matrixPower_vector[i])]

        # c vector is coefficient vector for powers of matrix in characteristic equation
        c=[Ciphertext(trace_vector[0])]
        evaluator.negate(c[0])

        # application of  newton identities to find coefficient {refer to paper cited above}
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
        # creating null matrix of size n*n
        # can be parallelized
        for i in range(n):
            k_i=[]
            for j in range(n):
                enc_dat=Ciphertext()
                encryptor.encrypt(encoderF.encode(0), enc_dat)
                k_i.append(enc_dat)
            K_inv.append(k_i)

        # Adding the matrices multiplied by their coefficients
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
    def parallel_plainMultiplication(element,D):
        # have to create new ciphertext object as row X column multiplication of matrix enforces no change in matrix elements
        evaluator.multiply_plain(element, D)

    @staticmethod
    def multiplyDeterminant(M, determinant):
        p=Plaintext()
        # need to send user D so that user can send back -1/D either in encrypted form or decrypted form
        decryptor.decrypt(determinant, p)
        d= (-1/encoderF.decode(p))
        delta=encoderF.encode(d)
        plainMul_pool = multiprocessing.Pool(processes=num_cores)
        del(p)

        for i in range(len(M)):
            plainMul_pool.map(partial(matrixOperations.parallel_plainMultiplication,determinant= delta), M[i])
        plainMul_pool.close()


########################## rest of functions neeeded ###########################


def print_plain(D):
    # function to print out all elements in a matrix
    if ( type(D[0]) != list ):
        for element in D:
            p=Plaintext()
            decryptor.decrypt(element, p)
            print(encoderF.decode(p), end=" ")
        print()

    else:
        for row in D:
            for values in row:
                p=Plaintext()
                decryptor.decrypt(values, p)
                print(encoderF.decode(p), end=" ")
            print()

def print_value(s):
    # print value of an encoded ciphertext
    p=Plaintext()
    decryptor.decrypt(s,p)
    print(encoderF.decode(p))

def normalize(M):
    # normalizes raw data on user end
    for i in range(len(M)):
        maxR=max(M[i])
        minR=min(M[i])
        for j in range(len(M[i])):
            M[i][j]= (M[i][j] - minR) / float(maxR-minR)
    return(M)

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
    return(enc_M)


if __name__ == '__main__':

    multiprocessing.freeze_support()

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

    num_cores = multiprocessing.cpu_count() - 1

    print(num_cores)


    ########################## encoding main matrix ################################


    dir_path=os.path.dirname(os.path.realpath(__file__))

    #################### covariate matrix and derivatives ##########################

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


    ###################### encrypting tX and y #####################################
    print("[+] Starting enrypting matrices")
    X=[]
    for i in range(4):
        x=[]
        for j in range(4):
            x.append(random.randint(0,10))
        print(x)
        X.append(x)

    X= encrypting_Matrix(X)
    #encrypting y
    y_encrypted= encrypting_Matrix(y)
    try:
        del(y)
    except:
        pass

    gc.collect()

    print("[+] Encrypted X and y")


    ########################## linear regression Pt. 1 ##############################

    print("\n[+] Proceding to homomorphic functions")

    # dimension of X ->  n (number of individuals) rows and 1+k (1+ number of covariates) cols
    # dimension of y -> vector of length n (number of individuals)
    # dimension of S ->  n (number of individuals) rows and m (number of SNPs)


    #restricting to 10 for calculation  purposes
       #########
    y_encrypted=y_encrypted[:10]
    k= len(X[0]) # k= 3

    print("Y : ")
    print_plain(y_encrypted)

    for elementY in y_encrypted:
        evaluator.square(elementY)
    y_star2=y_encrypted
    del(y_encrypted)

    print("\nY squared: ")
    print_plain(y_star2)



    print("\nrandom X : ")
    print_plain(X)
    X_star=matrixOperations.colSquare_Sum(X)
    # dimension of S_star2 -> vector of length m (number of SNPs)

    print("\nCol Squared X : ")
    print_plain(X)
    print_plain(X_star)
    print("[=] Finished with homomorphic functions")
    
