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
            
def plotFeatures(features,oClass,f1index=0,f2index=1):
    nObs,nFea=features.shape
    colors=['b','g','r']
    for i in range(nObs):
        plt.plot(features[i,f1index],features[i,f2index],'o'+colors[int(oClass[i])])

    plt.show()
    waitforEnter()
    
def logplotFeatures(features,oClass,f1index=0,f2index=1):
    nObs,nFea=features.shape
    colors=['b','g','r']
    for i in range(nObs):
        plt.loglog(features[i,f1index],features[i,f2index],'o'+colors[int(oClass[i])])

    plt.show()
    waitforEnter()

Classes={0:'Normal',1:'Malicious'}
plt.ion()
nfig=1

# load features data

features_normal=np.loadtxt("Normal_obs_features.dat")
features_malicious=np.loadtxt("Malicious_obs_features.dat")

oClass_normal=np.ones((len(features_normal),1))*0
oClass_malicious=np.ones((len(features_malicious),1))*1

features=np.vstack((features_normal,features_malicious))
oClass=np.vstack((oClass_normal,oClass_malicious))

print('Train Stats Features Size:',features.shape)

plt.figure(4)
plotFeatures(features,oClass,0,1)


# load silence data

features_normalSilence=np.loadtxt("Normal_obs_sil_features.dat")
features_maliciousSilence=np.loadtxt("Malicious_obs_sil_features.dat")

featuresSilence=np.vstack((features_normalSilence,features_maliciousSilence))
oClass=np.vstack((oClass_normal,oClass_malicious))

print('Train Silence Features Size:',featuresSilence.shape)

plt.figure(5)
plotFeatures(featuresSilence,oClass,0,2)

# load training data

percentage=0.5
pN=int(len(features_normal)*percentage)
trainFeatures_normal=features_normal[:pN,:]
pM=int(len(features_malicious)*percentage)
trainFeatures_malicious=features_malicious[:pM,:]

trainFeatures=np.vstack((trainFeatures_normal,trainFeatures_malicious))

trainFeatures_normalSilence=features_normalSilence[:pN,:]
trainFeatures_maliciousSilence=features_maliciousSilence[:pM,:]

trainFeaturesSilence=np.vstack((trainFeatures_normalSilence,trainFeatures_maliciousSilence))

o2trainClass=np.vstack((oClass_normal[:pN],oClass_malicious[:pM]))
#i2trainFeatures=np.hstack((trainFeatures,trainFeaturesS,trainFeaturesW))
i2trainFeatures=np.hstack((trainFeatures,trainFeaturesSilence))
#i2trainFeatures=trainFeatures

# load test data

testFeatures_normal=features_normal[pN:,:]
testFeatures_malicious=features_malicious[pM:,:]

testFeatures=np.vstack((testFeatures_normal,testFeatures_malicious))

testFeatures_normalSilence=features_normalSilence[pN:,:]
testFeatures_maliciousSilence=features_maliciousSilence[pM:,:]

testFeaturesSilence=np.vstack((testFeatures_normalSilence,testFeatures_maliciousSilence))

o3testClass=np.vstack((oClass_normal[pN:],oClass_malicious[pM:]))
#i3testFeatures=np.hstack((testFeatures,testFeaturesS,testFeaturesW))
i3testFeatures=np.hstack((testFeatures,testFeaturesSilence))
#i3testFeatures=testFeatures

# features scaler (data normalization)

from sklearn.preprocessing import MaxAbsScaler

i2trainScaler = MaxAbsScaler().fit(i2trainFeatures)
i2trainFeaturesN=i2trainScaler.transform(i2trainFeatures)

#i3trainScaler = MaxAbsScaler().fit(i3trainFeatures)  
#i3trainFeaturesN=i3trainScaler.transform(i3trainFeatures)

i3AtestFeaturesN=i2trainScaler.transform(i3testFeatures)
#i3CtestFeaturesN=i3trainScaler.transform(i3testFeatures)

print(np.mean(i2trainFeaturesN,axis=0))
print(np.std(i2trainFeaturesN,axis=0))

# SVM detection training

from sklearn import svm

print('\n-- Anomaly Detection based on One Class Support Vector Machines --')
ocsvm = svm.OneClassSVM(gamma='scale',kernel='linear').fit(i2trainFeaturesN)  
rbf_ocsvm = svm.OneClassSVM(gamma='scale',kernel='rbf').fit(i2trainFeaturesN)  
poly_ocsvm = svm. OneClassSVM(gamma='scale',kernel='poly',degree=2).fit(i2trainFeaturesN)  

# SVM detection predict

L1=ocsvm.predict(i3AtestFeaturesN)
L2=rbf_ocsvm.predict(i3AtestFeaturesN)
L3=poly_ocsvm.predict(i3AtestFeaturesN)

AnomResults={-1:"MALICIOUS",1:"NORMAL"}

nObsTest,nFea=i3AtestFeaturesN.shape
for i in range(nObsTest):
    print('Obs: {:2} ({:<8}): Kernel Linear->{:<10} | Kernel RBF->{:<10} | Kernel Poly->{:<10}'.format(i,Classes[o3testClass[i][0]],AnomResults[L1[i]],AnomResults[L2[i]],AnomResults[L3[i]]))

