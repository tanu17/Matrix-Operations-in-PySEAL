#!/usr/bin/env python3
from functools import partial
import random
import math
import os
import numpy
import time
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


class matrixOperations:

    @staticmethod
    def dot_vector(row,col,empty_ctext):
        l=len(row)
        for i in range(l):
            # multiply/binary operation between vectors
            # can define new dit-vector operation here
            cVec=Ciphertext()
            evaluator.multiply(row[i], col[i], cVec)
            evaluator.add(empty_ctext, cVec)
            #if (count==2):
            #   evaluator.relinearize(empty_ctext, ev_keys20)

    @staticmethod
    def matMultiply(T,K):
    # multipliess two matrix and returns a new matrix as result
        X=[]

        if ( type(K[0]) != list ):
            # K is a vector instead of matrix
            print("Dimension of T: %dx%d\nDimension of K: %dx1\n"%(len(T),len(T[0]),len(K)))

            for i in range(len(T)):
                # print("K vector: ",i)
                X.append(matrixOperations.dot_vector(T[i], K))


        elif (type(T[0]) != list ):
            # K is a vector instead of matrix

            tK=[list(tup) for tup in zip(*K)]
            print("Dimension of T: %dx1\nDimension of K: %dx%d\n"%(len(T),len(K),len(K[0])))
            del(K)

            for i in range(len(tK)):
                X.append( matrixOperations.dot_vector(tK[i], T) )

        else:
            tK=[list(tup) for tup in zip(*K)]
            print("Dimension of T: %dx%d\nDimension of K: %dx%d"%(len(T),len(T[0]),len(K),len(K[0])))

            for i in range(len(T)):
                row_X=[]
                for j in range(len(tK)):
                    temp= Ciphertext()
                    encryptor.encrypt(encoderF.encode(0), temp)
                    dot_vector(M[i], tA[j],temp)
                    row_X.append(temp)
                X.append( row_X )

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
        print(M)
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
            print(len(matrixPower_vector))
            matrixPower_vector+=matrixOperations.matMultiply(K, matrixPower_vector[i-1])
            trace_vector+=(matrixOperations.trace(matrixPower_vector[i]))

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
    for i in range(len(M)):
        maxR=max(M[i])
        minR=min(M[i])
        for j in range(len(M[i])):
            M[i][j]= (M[i][j] - minR) / float(maxR-minR)
    return(M)

def encode_Matrix(row):
    global 
    x=[]
    for element in row:
        x.append(encoderF.encode(element))
    return(x)

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



parms = EncryptionParameters()
parms.set_poly_modulus("1x^8192 + 1")
parms.set_coeff_modulus(seal.coeff_modulus_128(8192))
parms.set_plain_modulus(1 << 21)
context = SEALContext(parms)

#encoder = IntegerEncoder(context.plain_modulus())
encoderF = FractionalEncoder(context.plain_modulus(), context.poly_modulus(), 30, 34, 3) 
keygen = KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()
#ev_keys40 = EvaluationKeys
#ev_keys20 = EvaluationKeys()
#keygen.generate_evaluation_keys(40,5,ev_keys40)
#keygen.generate_evaluation_keys(20,3,ev_keys20)
encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)


plain_A = []
A=[]
n=int(input("Enter dimension: "))

for i in range(n):
    plain_a = []
    a=[]
    for j in range(n):
        encrypted_data1= Ciphertext()
        ran=random.randint(0,10)
        plain_a.append(ran)
        encryptor.encrypt(encoderF.encode(ran), encrypted_data1)
        a.append(encrypted_data1)
    A.append(a)
    plain_A.append(plain_a)
    print(plain_a)

delta, C = matrixOperations.inverseMatrix(A)

print(delta)