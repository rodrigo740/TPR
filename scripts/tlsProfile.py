import numpy as np
import scipy.stats as stats
import scipy.signal as signal
import matplotlib.mlab as mlab
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import time
import sys
import warnings
warnings.filterwarnings('ignore')


def waitforEnter(fstop=False):
    if fstop:
        if sys.version_info[0] == 2:
            raw_input("Press ENTER to continue.")
        else:
            input("Press ENTER to continue.")
            
## -- 4 -- ##
def plotFeatures(features,oClass,f1index=0,f2index=1):
    nObs,nFea=features.shape
    colors=['b','g','r']
    for i in range(nObs):
        plt.plot(features[i,f1index],features[i,f2index],'o'+colors[int(oClass[i])])

    plt.show(block=True)
    waitforEnter()
    
def logplotFeatures(features,oClass,f1index=0,f2index=1):
    nObs,nFea=features.shape
    colors=['b','g','r']
    for i in range(nObs):
        plt.loglog(features[i,f1index],features[i,f2index],'o'+colors[int(oClass[i])])

    plt.show(block=True)
    waitforEnter()
    
## -- 11 -- ##
def distance(c,p):
    return(np.sqrt(np.sum(np.square(p-c))))

########### Main Code #############
Classes={0:'Normal',1:'Malicious'}
plt.ion()
nfig=1

## -- 3 -- ##
features_normal=np.loadtxt("normal_obs_features.dat")

oClass_normal=np.ones((len(features_normal),1))*0

features=np.vstack((features_normal))
oClass=np.vstack((oClass_normal))

print('Train Stats Features Size:',features.shape)

## -- 4 -- ##
#plt.figure(4)
#plotFeatures(features,oClass,3,4)

## -- 5 -- ##
features_normalS=np.loadtxt("normal_obs_sil_features.dat")

featuresS=np.vstack((features_normalS))
oClass=np.vstack((oClass_normal))

print('Train Silence Features Size:',featuresS.shape)
#plt.figure(5)
#plotFeatures(featuresS,oClass,0,2)

## -- 8 -- ##
#:1
percentage=1.0
pN=int(len(features_normal)*percentage)
trainFeatures_normal=features_normal[:pN,:]

trainFeatures=np.vstack((trainFeatures_normal))

trainFeatures_normalS=features_normalS[:pN,:]

trainFeaturesS=np.vstack((trainFeatures_normalS))

o2trainClass=np.vstack((oClass_normal[:pN]))
#i2trainFeatures=np.hstack((trainFeatures,trainFeaturesS,trainFeaturesW))
i2trainFeatures=np.hstack((trainFeatures,trainFeaturesS))
#i2trainFeatures=trainFeatures

#:3

attack_features_data = np.loadtxt("malicious_obs_features.dat")
testFeatures_normal=attack_features_data

testFeatures=np.vstack((testFeatures_normal))

attack_silence_features_data = np.loadtxt("malicious_obs_sil_features.dat")
testFeatures_normalS=attack_silence_features_data

testFeaturesS=np.vstack((testFeatures_normalS))

o3testClass=np.vstack((oClass_normal))
#i3testFeatures=np.hstack((testFeatures,testFeaturesS,testFeaturesW))
i3testFeatures=np.hstack((testFeatures,testFeaturesS))
#i3testFeatures=testFeatures

#plt.figure(5)
#plotFeatures(testFeatures,o3testClass,0,1)

## -- 9 -- ##
from sklearn.preprocessing import MaxAbsScaler

i2trainScaler = MaxAbsScaler().fit(i2trainFeatures)
i2trainFeaturesN=i2trainScaler.transform(i2trainFeatures)

i3AtestFeaturesN=i2trainScaler.transform(i3testFeatures)

print(np.mean(i2trainFeaturesN,axis=0))
print(np.std(i2trainFeaturesN,axis=0))

## -- 10 -- ##
from sklearn.decomposition import PCA

pca = PCA(n_components=3, svd_solver='full')

i2trainPCA=pca.fit(i2trainFeaturesN)
i2trainFeaturesNPCA = i2trainPCA.transform(i2trainFeaturesN)

i3AtestFeaturesNPCA = i2trainPCA.transform(i3AtestFeaturesN)

print(i2trainFeaturesNPCA.shape,o2trainClass.shape)
#plt.figure(8)
#plotFeatures(i2trainFeaturesNPCA,o2trainClass,0,1)

## -- 11 -- ##
from sklearn.preprocessing import MaxAbsScaler
centroids={}
for c in range(1):  # Only the first class
    pClass=(o2trainClass==c).flatten()
    centroids.update({c:np.mean(i2trainFeaturesN[pClass,:],axis=0)})
#print('All Features Centroids:\n',centroids)

anomalies = 0

AnomalyThreshold=1.2
print('\n-- Anomaly Detection based on Centroids Distances --')
nObsTest,nFea=i3AtestFeaturesN.shape
for i in range(nObsTest):
    x=i3AtestFeaturesN[i]
    dists=[distance(x,centroids[0])]
    if min(dists)>AnomalyThreshold:
        result="Anomaly"
        anomalies += 1
    else:
        result="OK"
       
    #print('Obs: {:2} ({}): Normalized Distances to Centroids: [{:.4f},{:.4f}] -> Result -> {}'.format(i,Classes[o3testClass[i][0]],*dists,result))
print('\n-- Number of Malicious Flows(%): {:0.2f} % --\n'.format(anomalies/nObsTest*100))

## -- 12 -- ##
centroids={}
for c in range(1):  # Only the first class
    pClass=(o2trainClass==c).flatten()
    centroids.update({c:np.mean(i2trainFeaturesNPCA[pClass,:],axis=0)})
#print('All Features Centroids:\n',centroids)

anomalies = 0

AnomalyThreshold=1.2
print('\n-- Anomaly Detection based on Centroids Distances (PCA Features) --')
nObsTest,nFea=i3AtestFeaturesNPCA.shape
for i in range(nObsTest):
    x=i3AtestFeaturesNPCA[i]
    dists=[distance(x,centroids[0])]
    if min(dists)>AnomalyThreshold:
        result="Anomaly"
        anomalies += 1
    else:
        result="OK"
       
    #print('Obs: {:2} ({}): Normalized Distances to Centroids: [{:.4f},{:.4f}] -> Result -> {}'.format(i,Classes[o3testClass[i][0]],*dists,result))
print('\n-- Number of Malicious Flows(%): {:0.2f} % --\n'.format(anomalies/nObsTest*100))


## -- 13 -- ##
from scipy.stats import multivariate_normal
print('\n-- Anomaly Detection based Multivariate PDF (PCA Features) --')
means={}
for c in range(1):
    pClass=(o2trainClass==c).flatten()
    means.update({c:np.mean(i2trainFeaturesNPCA[pClass,:],axis=0)})
#print(means)

covs={}
for c in range(1):
    pClass=(o2trainClass==c).flatten()
    covs.update({c:np.cov(i2trainFeaturesNPCA[pClass,:],rowvar=0)})
#print(covs)

anomalies = 0

AnomalyThreshold=0.05
nObsTest,nFea=i3AtestFeaturesNPCA.shape
for i in range(nObsTest):
    x=i3AtestFeaturesNPCA[i,:]
    probs=np.array([multivariate_normal.pdf(x,means[0],covs[0])])
    if max(probs)<AnomalyThreshold:
        result="Anomaly"
        anomalies += 1
    else:
        result="OK"
    
    #print('Obs: {:2} ({}): Probabilities: [{:.4e},{:.4e}] -> Result -> {}'.format(i,Classes[o3testClass[i][0]],*probs,result))
print('\n-- Number of Malicious Flows(%): {:0.2f} % --\n'.format(anomalies/nObsTest*100))


## -- 14 -- ##
from sklearn import svm

print('\n-- Anomaly Detection based on One Class Support Vector Machines (PCA Features) --')
ocsvm = svm.OneClassSVM(gamma='scale',kernel='linear').fit(i2trainFeaturesNPCA)  
rbf_ocsvm = svm.OneClassSVM(gamma='scale',kernel='rbf').fit(i2trainFeaturesNPCA)  
poly_ocsvm = svm. OneClassSVM(gamma='scale',kernel='poly',degree=2).fit(i2trainFeaturesNPCA)  

L1=ocsvm.predict(i3AtestFeaturesNPCA)
L2=rbf_ocsvm.predict(i3AtestFeaturesNPCA)
L3=poly_ocsvm.predict(i3AtestFeaturesNPCA)

AnomResults={-1:"Anomaly",1:"OK"}

sums = [0, 0, 0]

nObsTest,nFea=i3AtestFeaturesNPCA.shape
for i in range(nObsTest):
    #print('Obs: {:2} ({:<8}): Kernel Linear->{:<10} | Kernel RBF->{:<10} | Kernel Poly->{:<10}'.format(i,Classes[o3testClass[i][0]],AnomResults[L1[i]],AnomResults[L2[i]],AnomResults[L3[i]]))
    if L1[i] == -1:
        sums[0] = sums[0] + 1
    if L2[i] == -1:
        sums[1] = sums[1] + 1
    if L3[i] == -1:
        sums[2] = sums[2] + 1

print('\n-- Number of Malicious Flows(%): Kernel Linear -> {:0.2f} % | Kernel RBF -> {:0.2f} % | Kernel Poly -> {:0.2f} % --\n'.format(sums[0]/nObsTest*100,sums[1]/nObsTest*100,sums[2]/nObsTest*100))

## -- 15 -- ##
from sklearn import svm

print('\n-- Anomaly Detection based on One Class Support Vector Machines --')
ocsvm = svm.OneClassSVM(gamma='scale',kernel='linear').fit(i2trainFeaturesN)  
rbf_ocsvm = svm.OneClassSVM(gamma='scale',kernel='rbf').fit(i2trainFeaturesN)  
poly_ocsvm = svm. OneClassSVM(gamma='scale',kernel='poly',degree=2).fit(i2trainFeaturesN)  

L1=ocsvm.predict(i3AtestFeaturesN)
L2=rbf_ocsvm.predict(i3AtestFeaturesN)
L3=poly_ocsvm.predict(i3AtestFeaturesN)

AnomResults={-1:"Anomaly",1:"OK"}

sums = [0, 0, 0]

nObsTest,nFea=i3AtestFeaturesN.shape
for i in range(nObsTest):
   #print('Obs: {:2} ({:<8}): Kernel Linear->{:<10} | Kernel RBF->{:<10} | Kernel Poly->{:<10}'.format(i,Classes[o3testClass[i][0]],AnomResults[L1[i]],AnomResults[L2[i]],AnomResults[L3[i]]))
    if L1[i] == -1:
        sums[0] = sums[0] + 1
    if L2[i] == -1:
        sums[1] = sums[1] + 1
    if L3[i] == -1:
        sums[2] = sums[2] + 1

print('\n-- Number of Malicious Flows(%): Kernel Linear -> {:0.2f} % | Kernel RBF -> {:0.2f} % | Kernel Poly -> {:0.2f} % --\n'.format(sums[0]/nObsTest*100,sums[1]/nObsTest*100,sums[2]/nObsTest*100))

