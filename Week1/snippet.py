import kagglehub
from kagglehub import KaggleDatasetAdapter

# Set the path to the file you'd like to load
# Note: The dataset contains: 'Modified_SQL_Dataset.csv'
file_path = "Modified_SQL_Dataset.csv"

# Pass kwargs to pandas to handle encoding and avoid deprecation
df = kagglehub.dataset_load(
  KaggleDatasetAdapter.PANDAS,
  "sajid576/sql-injection-dataset",
  file_path,
  pandas_kwargs={"encoding": "utf-8", "on_bad_lines": "skip"}
)

print(f"First 5 records of {file_path}:\n", df.head())
