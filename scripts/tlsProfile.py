import numpy as np
import joblib
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

plt.ion()
nfig=1

# load features data

features_normal=np.loadtxt("normal_obs_features.dat")

features=np.vstack((features_normal))

print('Train Stats Features Size:',features.shape)

# load silence data

features_normalSilence=np.loadtxt("normal_obs_sil_features.dat")

featuresSilence=np.vstack((features_normalSilence))

print('Train Silence Features Size:',featuresSilence.shape)

# load training data

percentage=1.0  # use 100% of the data for testing
pN=int(len(features_normal)*percentage)
trainFeatures_normal=features_normal[:pN,:]

trainFeatures=np.vstack((trainFeatures_normal))

trainFeatures_normalSilence=features_normalSilence[:pN,:]

trainFeaturesSilence=np.vstack((trainFeatures_normalSilence))

i2trainFeatures=np.hstack((trainFeatures,trainFeaturesSilence))

# features scaler (data normalization)

from sklearn.preprocessing import MaxAbsScaler

i2trainScaler = MaxAbsScaler().fit(i2trainFeatures)
i2trainFeaturesN=i2trainScaler.transform(i2trainFeatures)

print(np.mean(i2trainFeaturesN,axis=0))
print(np.std(i2trainFeaturesN,axis=0))

# one class SVM anomaly detection training

from sklearn import svm

print('\n-- Anomaly Detection based on One Class Support Vector Machines --')
ocsvm = svm.OneClassSVM(gamma='scale',kernel='linear').fit(i2trainFeaturesN)  
rbf_ocsvm = svm.OneClassSVM(gamma='scale',kernel='rbf').fit(i2trainFeaturesN)  
poly_ocsvm = svm.OneClassSVM(gamma='scale',kernel='poly',degree=2).fit(i2trainFeaturesN)  

# save models

joblib.dump(ocsvm, type(ocsvm).__name__+"(linear).model", compress=9)
joblib.dump(rbf_ocsvm, type(rbf_ocsvm).__name__+"(rbf).model", compress=9)
joblib.dump(poly_ocsvm, type(poly_ocsvm).__name__+"(poly).model", compress=9)
