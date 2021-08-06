#!/usr/bin/env python
# coding: utf-8

# In[1]:


import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import pickle


# In[ ]:


df=pd.read_csv('KDD20train.csv')


# In[ ]:


df.info()


# In[ ]:


coll=df[['protocol_type','land','urgent','count','srv_count','dst_host_count','dst_host_srv_count','class']]


# In[ ]:


coll.head()


# In[ ]:


from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
coll['class'] = le.fit_transform(coll['class'])
coll['protocol_type']=le.fit_transform(coll['protocol_type'])


# In[ ]:


x_train = coll.iloc[:,:-1].values
y_train = coll.iloc[:,-1].values


# In[ ]:


coll.head()


# In[ ]:


from sklearn.tree import DecisionTreeClassifier
clf = DecisionTreeClassifier(random_state=0)
clf.fit(x_train,y_train)



# In[ ]:


""" filename = 'finalized_model.sav'
pickle.dump(clf, open(filename, 'wb'))

 #Uncomment this when you try to generate the model """


# In[ ]:


dftest=pd.read_csv('KDD20train.csv')
dftest.head()


# In[ ]:


colltest=dftest[['protocol_type','land','urgent','count','srv_count','dst_host_count','dst_host_srv_count','class']]


# In[ ]:


colltest.head()


# In[ ]:


from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
colltest['class'] = le.fit_transform(colltest['class'])
colltest['protocol_type']=le.fit_transform(colltest['protocol_type'])



x_test = colltest.iloc[:,:-1].values
y_test = colltest.iloc[:,-1].values


y_pred=clf.predict(x_test)



from sklearn.metrics import accuracy_score
accuracy_LogisticRegression = clf.score(x_test,y_test)
print("accuracy  "+str(accuracy_LogisticRegression))


# In[ ]:


from sklearn.metrics import mean_absolute_error,mean_squared_error
mae=mean_absolute_error(y_test,y_pred)
mse=mean_squared_error(y_test,y_pred)
print("mean absolute error",mae)
rmse=np.sqrt(mse)
print("root mean square error",rmse)



from sklearn.metrics import recall_score,precision_score,f1_score
rec=recall_score(y_test,y_pred)
prec=precision_score(y_test,y_pred)
f1=f1_score(y_test,y_pred)
print("recall -",rec)
print("precision -",prec)
print("f1_score -",f1)

