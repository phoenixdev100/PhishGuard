import numpy as np
from sklearn.ensemble import RandomForestClassifier
import pickle

# Generate sample data
np.random.seed(42)
n_samples = 1000

# Simple features
features = np.random.rand(n_samples, 4)  # 4 simple features
labels = np.random.randint(0, 2, n_samples)  # Binary labels: 0 or 1

# Train a simple Random Forest model
model = RandomForestClassifier(n_estimators=10, random_state=42)
model.fit(features, labels)

# Save the model using pickle
with open('phishing_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("Model trained and saved successfully!")