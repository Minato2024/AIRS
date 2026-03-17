import seaborn as sns
import pandas as pd
import os
# data\dionaea_logs.csv
def wrangle(filepath):

    pass

# sns.boxplot(x="time", y="total_bill", data=df)
# plt.show()

path = r"C:\\Users\\User\\Documents\\AIRS\\data\\dionaea_logs.csv"
assert os.path.isfile(path)

df= pd.read_csv(path)
print(df.columns)
print(df.describe())