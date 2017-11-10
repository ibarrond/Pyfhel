from Pyfhel import Pyfhel
from PyPtxt import PyPtxt
from PyCtxt import PyCtxt
import numpy as np
import time
import math

HE = Pyfhel()
def runTest(fileName, testID, p=257, r=1, d=1, c=2, sec=80, w=64, L=10, m=-1, R=3, s=0, gens=[], ords=[]):

    KEYGEN_PARAMS={ "p":257,      "r":1,
                    "d":1,        "c":2,
                    "sec":80,     "w":64,
                    "L":10,       "m":-1,
                    "R":3,        "s":0,
                    "gens":[],    "ords":[]}
   
    KEYGEN_PARAMS['p']=p   
    KEYGEN_PARAMS['r']=r   
    KEYGEN_PARAMS['d']=d   
    KEYGEN_PARAMS['c']=c   
    KEYGEN_PARAMS['sec']=sec
    KEYGEN_PARAMS['w']=w
    KEYGEN_PARAMS['L']=L
    KEYGEN_PARAMS['m']=m
    KEYGEN_PARAMS['R']=R
    KEYGEN_PARAMS['s']=s
    KEYGEN_PARAMS['gens']=gens
    KEYGEN_PARAMS['ords']=ords

    print("Pyfhel TEST %d"%(testID))
    print(" File: "+fileName)

    # KEYGEN
    print(" KEYGEN")
    print("  Running KeyGen with params:")
    print(KEYGEN_PARAMS)
    tic_keyGen = time.time()
    HE.keyGen(KEYGEN_PARAMS)
    toc_keyGen = time.time()
    print("  KeyGen completed")
    print("  nSlots = %d"%(HE.numSlots()))

    # DATA CREATION
    v1 = [1,2,3,4,5,6,7,8,9,10]
    v2 = [2,2,2,2,2,2,2,2,2,2]
    v3 = [1,1,1,1,1,1,1,1,1,1]
    p1 = PyPtxt(v1, HE)
    p2 = PyPtxt(v2, HE)
    p3 = PyPtxt(v3, HE)

    # ENCRYPTION
    print(" ENCRYPTION")
    print("  Encrypting p1, p2, p3 into c1, c2, c3")
    tic_Encr = time.time()
    c1 = HE.encrypt(p1)
    c2 = HE.encrypt(p2)
    c3 = HE.encrypt(p3)
    toc_Encr = time.time()
    t_e = toc_Encr - tic_Encr
    print("  Encryption completed")
    
    # TIMING OPERATIONS
    print(" OPERATIONS")
    print("  c1 += c2")
    tic_Sum = time.time()
    c1 += c2
    e1 = list(np.mod(np.array(v1)+np.array(v2), math.pow(p, r)))
    toc_Sum = time.time()
    tic_Decr_Sum = time.time()
    res1 = HE.decrypt(c1)
    toc_Decr_Sum = time.time()
    t_sum = toc_Sum - tic_Sum
    t_d_sum = toc_Decr_Sum - tic_Decr_Sum
    f_sum = res1[0] == e1
    print("    Result: "+str(res1[0]))
    print("    Debug: "+str(e1))

    print("  c1 *= c2")
    c1 = HE.encrypt(p1)
    tic_Prod = time.time()
    c1 *= c2
    e2 = list(np.mod(np.array(v1) * np.array(v2), math.pow(p,r)))
    toc_Prod = time.time()
    tic_Decr_Prod = time.time()
    res2 = HE.decrypt(c1)
    toc_Decr_Prod = time.time()
    t_prod = toc_Prod - tic_Prod
    t_d_prod = toc_Decr_Prod - tic_Decr_Prod
    f_prod = res2[0] == e2
    print("    Result: "+str(res2[0]))
    print("    Debug: "+str(e2))

    print("  c1 %= c2")
    c1 = HE.encrypt(p1)
    tic_scpr = time.time()
    c1 %= c2
    e3 = np.mod(sum(np.mod((np.array(v1) * np.array(v2)), math.pow(p,r))),math.pow(p,r))
    toc_scpr = time.time()
    tic_Decr_scpr = time.time()
    res3 = HE.decrypt(c1)
    toc_Decr_scpr = time.time()
    t_scpr = toc_scpr - tic_scpr
    t_d_scpr = toc_Decr_scpr - tic_Decr_scpr
    f_scpr = res3[0][0] == e3
    print("    Result: "+str(res3[0][0]))
    print("    Debug: "+str(e3))

    # CHECKING LIMITS
    print("  Maximum number of Sums")
    t_maxSum = 0
    t_maxSd = 0
    n_maxSum = 0
    resCorrect = 1
    a = np.array(v2)
    b = np.array(v3)
    while (resCorrect):
        tic_aux = time.time()
        c2 += c3
        toc_aux = time.time()
        a = list(a + b)
        tic_ad = time.time()
        res_aux = HE.decrypt(c2)
        toc_ad = time.time()
        resCorrect = (a == res_aux[0])
        n_maxSum += 1
        t_maxSum += (toc_aux - tic_aux)
        t_maxSd += (toc_ad - tic_ad)
    n_maxSum -= 1

    print("  Maximum number of Mults")
    t_maxMult = 0
    t_maxMd = 0
    n_maxMult = 0
    resCorrect = 1
    v2 = [2,2,2,2,2,2,2,2,2,2]
    p2 = PyPtxt(v2, HE)
    c2 = HE.encrypt(p2)
    a = np.array(v2)
    while (resCorrect):
        tic_aux = time.time()
        c2 *= c3
        toc_aux = time.time()
        ab = list(a * b)
        tic_ad = time.time()
        res_aux = HE.decrypt(c2)
        toc_ad = time.time()
        resCorrect = (ab == res_aux[0])
        n_maxMult += 1
        t_maxMult += (toc_aux - tic_aux)
        t_maxMd += (toc_ad - tic_ad)
    n_maxMult -= 1


    # SAVE KEYGEN DATA ON FILE
    f = open(fileName, 'a')
    f.write("----------------- TESTCASE %d ----------------\n"%(testID))
    f.write(" KeyGen: " + str(KEYGEN_PARAMS)+"\n")
    f.write(" -  nslots = %d\n"%(HE.numSlots()))
    f.write(" Encryption: t = %f\n"%(t_e))
    f.write(" SUM(%d): t = %f\n"%(f_sum, t_sum)) 
    f.write(" PROD(%d): t = %f\n"%(f_prod, t_prod)) 
    f.write(" SC.PROD(%d): t = %f\n"%(f_scpr, t_scpr)) 
    f.write(" LIMITS:\n")
    f.write("   - SUM: n = %d, t = %f t_avg = %f, td = %f, td_avg=%f\n"%(n_maxSum,
        t_maxSum, t_maxSum/n_maxSum, t_maxSd, t_maxSd/n_maxSum))
    f.write("   - PROD: n = %d, t = %f t_avg = %f, td = %f, td_avg=%f\n"%(n_maxMult,
        t_maxMult, t_maxMult/n_maxMult, t_maxMd, t_maxMd/n_maxMult))
    f.write("---------------------------------------------\n")
    f.close()

    return

# RUN THE ZILLION TESTS!
fN = 'ZillionTests1.txt'
i=0
for p,r in zip([3, 2, 2, 2, 2, 253, 257, 257, 257, 65537, 65537, 4294967311],
               [5, 16, 30, 40, 54, 5, 1, 2, 3, 4, 1, 2, 1]):
    for L in [10, 20, 30, 35, 40]:
        for d in [0,1]:
            i=i+1
            try:
                runTest(fN, i, p=p, r=r, L=L, d=d)
            except(ValueError):
                f = open(fN, 'a')
                f.write("\n TEST %d FAILED. \n"%(i))
                f.close()
