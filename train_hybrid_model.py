import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import train_test_split, cross_val_score
import joblib

# Update this import based on your project structure
from core.hybrid__waf__model import HybridWAFModel

def main():
    try:
        # Load dataset (ensure waf_training_logs.csv contains features + 'label')
        df = pd.read_csv('waf_training_logs.csv')
        print(f"Loaded dataset with {df.shape[0]} rows and {df.shape[1]} columns.")

        if 'label' not in df.columns:
            raise ValueError("Dataset must contain 'label' column")

        X = df.drop('label', axis=1)
        y = df['label'].values

        # One-hot encode categorical features
        X = pd.get_dummies(X)
        print(f"Features after one-hot encoding: {X.shape[1]}")

        # Stratified train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y)
        print(f"Training samples: {X_train.shape[0]}, Test samples: {X_test.shape[0]}")

        # Balance classes with SMOTE
        smote = SMOTE(random_state=42)
        X_res, y_res = smote.fit_resample(X_train, y_train)
        print(f"After SMOTE, training set class distribution: {np.bincount(y_res)}")

        # Initialize your Hybrid WAF model
        model = HybridWAFModel(random_state=42)

        # Use at most 5-fold cross-validation or less if minority class is small
        min_class_count = np.min(np.bincount(y_res))
        cv_folds = min(5, min_class_count)
        print(f"Using {cv_folds}-fold cross-validation")

        # Cross-validation performance
        scores = cross_val_score(model.meta_classifier, X_res, y_res, cv=cv_folds, scoring='accuracy')
        print(f"Cross-validation accuracy: {scores.mean():.3f} ± {scores.std():.3f}")

        # Train on full resampled data
        model.train(X_res, y_res)

        # Final evaluation on test set
        test_accuracy = model.score(X_test, y_test)
        print(f"Test set accuracy: {test_accuracy:.3f}")

        # Save the retrained model
        joblib.dump(model, 'hybrid_waf_model.joblib')
        print("Model saved to 'hybrid_waf_model.joblib'")

    except FileNotFoundError:
        print("Training data file 'waf_training_logs.csv' not found.")
    except Exception as e:
        print(f"Error during training: {e}")

if __name__ == '__main__':
    main()
