import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import RandomizedSearchCV, train_test_split

data = pd.read_csv('Normal_Traffic.csv')
X = data.drop('Label', axis=1)
y = data['Label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

forest = RandomForestClassifier()
#param_dist = {'n_estimators': randint(50, 500),
#                'max_depth': randint(1, 20)}
#rand_search = RandomizedSearchCV(forest,
#                                    param_distributions=param_dist,
#                                    n_iter=5,
#                                    cv=5)
#rand_search.fit(X_train, y_train)
#best_forest = rand_search.best_estimator_

#y_pred = best_forest.predict(X_test)

forest.fit(X_train, y_train)
y_pred = forest.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(classification_report(y_test, y_pred))
print(accuracy)
