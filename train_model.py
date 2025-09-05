import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# Sample training data (attempts, time_taken)
# 0 = normal user, 1 = attacker
X = [
    [1, 5], [2, 8], [1, 10],  # Normal
    [5, 35], [4, 45], [6, 55],  # Suspected attacker
    [3, 20], [2, 15], [6, 30],  # Mix
    [7, 50], [8, 60], [4, 70]   # More attackers
]

y = [0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1]

# Train model
model = RandomForestClassifier()
model.fit(X, y)

# Save the model
with open("intrusion_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model trained and saved to intrusion_model.pkl")
