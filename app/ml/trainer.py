"""
Model Training Pipeline for AIRS
Trains detection models on preprocessed Dionaea data
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any
from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import cross_val_score, GridSearchCV
import joblib
import json
from datetime import datetime
import structlog
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

logger = structlog.get_logger("airs.ml.trainer")


class ModelTrainer:
    """
    Train and evaluate machine learning models for threat detection.
    Supports both traditional ML and deep learning approaches.
    """
    
    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.models: Dict[str, Any] = {}
        self.metrics: Dict[str, Dict] = {}
        
        # Ensure model directory exists
        import os
        os.makedirs(model_dir, exist_ok=True)
    
    def train_binary_classifier(
        self, 
        X_train: np.ndarray, 
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        algorithm: str = "random_forest"
    ) -> Any:
        """
        Train binary classifier (attack vs normal).
        
        Args:
            X_train: Training features
            y_train: Binary labels (0=normal, 1=attack)
            algorithm: 'random_forest', 'gradient_boosting', 'logistic_regression', or 'neural_network'
        """
        logger.info("Training binary classifier", algorithm=algorithm)
        
        if algorithm == "random_forest":
            model = RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
                n_jobs=-1,
                random_state=42
            )
        elif algorithm == "gradient_boosting":
            model = GradientBoostingClassifier(
                n_estimators=200,
                max_depth=5,
                learning_rate=0.1,
                random_state=42
            )
        elif algorithm == "logistic_regression":
            model = LogisticRegression(
                class_weight='balanced',
                max_iter=1000,
                random_state=42
            )
        elif algorithm == "neural_network":
            return self._train_neural_network_binary(X_train, y_train, X_val, y_val)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        # Train
        model.fit(X_train, y_train)
        
        # Validate
        if X_val is not None and y_val is not None:
            y_pred = model.predict(X_val)
            accuracy = accuracy_score(y_val, y_pred)
            logger.info("Binary classifier validation", accuracy=accuracy)
        
        self.models['binary'] = model
        return model
    
    def train_category_classifier(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        algorithm: str = "random_forest"
    ) -> Any:
        """
        Train multi-class classifier for attack categories.
        """
        logger.info("Training category classifier", algorithm=algorithm)
        
        # Only train on attack samples (label=1)
        # If y_train is mixed, filter to attacks only for category training
        # Or use the full dataset if y_train is already categories
        
        if algorithm == "random_forest":
            model = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=10,
                class_weight='balanced',
                n_jobs=-1,
                random_state=42
            )
        elif algorithm == "gradient_boosting":
            model = GradientBoostingClassifier(
                n_estimators=150,
                max_depth=5,
                learning_rate=0.1,
                random_state=42
            )
        elif algorithm == "neural_network":
            return self._train_neural_network_category(X_train, y_train, X_val, y_val)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        model.fit(X_train, y_train)
        
        if X_val is not None and y_val is not None:
            y_pred = model.predict(X_val)
            accuracy = accuracy_score(y_val, y_pred)
            logger.info("Category classifier validation", accuracy=accuracy)
        
        self.models['category'] = model
        return model
    
    def train_anomaly_detector(
        self,
        X_train: np.ndarray,
        contamination: float = 0.1,
        algorithm: str = "isolation_forest"
    ) -> Any:
        """
        Train unsupervised anomaly detector on normal traffic.
        
        Args:
            X_train: Training features (should be mostly normal traffic)
            contamination: Expected proportion of outliers
        """
        logger.info("Training anomaly detector", algorithm=algorithm, contamination=contamination)
        
        if algorithm == "isolation_forest":
            model = IsolationForest(
                n_estimators=200,
                contamination=contamination,
                random_state=42,
                n_jobs=-1
            )
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        model.fit(X_train)
        
        self.models['anomaly'] = model
        return model
    
    def _train_neural_network_binary(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None
    ) -> keras.Model:
        """Train binary classification neural network"""
        logger.info("Training binary neural network")
        
        # Ensure labels are floats for binary_crossentropy
        y_train = np.asarray(y_train, dtype=np.float32)
        if y_val is not None:
            y_val = np.asarray(y_val, dtype=np.float32)
        
        input_dim = X_train.shape[1]
        
        model = keras.Sequential([
            layers.Input(shape=(input_dim,)),
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.3),
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.3),
            layers.Dense(32, activation='relu'),
            layers.Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        callbacks = [
            keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True),
            keras.callbacks.ReduceLROnPlateau(patience=3)
        ]
        
        validation_data = (X_val, y_val) if X_val is not None else None
        
        history = model.fit(
            X_train, y_train,
            epochs=50,
            batch_size=256,
            validation_data=validation_data,
            callbacks=callbacks,
            verbose=1
        )
        
        self.models['binary_nn'] = model
        return model
    
    def _train_neural_network_category(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None
    ) -> keras.Model:
        """Train multi-class classification neural network"""
        logger.info("Training category neural network")
        
        # Ensure labels are integers for sparse_categorical_crossentropy
        y_train = np.asarray(y_train, dtype=np.int32)
        if y_val is not None:
            y_val = np.asarray(y_val, dtype=np.int32)
        
        input_dim = X_train.shape[1]
        num_classes = len(np.unique(y_train))
        
        model = keras.Sequential([
            layers.Input(shape=(input_dim,)),
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.3),
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.3),
            layers.Dense(32, activation='relu'),
            layers.Dense(num_classes, activation='softmax')
        ])
        
        model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        callbacks = [
            keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True),
            keras.callbacks.ReduceLROnPlateau(patience=3)
        ]
        
        validation_data = (X_val, y_val) if X_val is not None else None
        
        history = model.fit(
            X_train, y_train,
            epochs=50,
            batch_size=256,
            validation_data=validation_data,
            callbacks=callbacks,
            verbose=1
        )
        
        self.models['category_nn'] = model
        return model
    
    def evaluate(
        self,
        model_name: str,
        X_test: np.ndarray,
        y_test: np.ndarray,
        target_names: Optional[List[str]] = None
    ) -> Dict:
        """
        Evaluate trained model on test set.
        """
        logger.info("Evaluating model", model=model_name)
        
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found. Train first.")
        
        model = self.models[model_name]
        
        # Predict
        if hasattr(model, 'predict_proba'):
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)
        elif isinstance(model, keras.Model):
            y_pred_proba = model.predict(X_test)
            y_pred = (y_pred_proba > 0.5).astype(int).flatten() if y_pred_proba.shape[1] == 1 else np.argmax(y_pred_proba, axis=1)
        else:
            y_pred = model.predict(X_test)
            y_pred_proba = None
        
        # Handle anomaly detector (returns -1 for anomaly, 1 for normal)
        if model_name == 'anomaly':
            y_pred = np.where(y_pred == -1, 1, 0)  # Convert to 0=normal, 1=anomaly
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, support = precision_recall_fscore_support(y_test, y_pred, average='weighted')
        
        # Get all unique labels to avoid confusion matrix warning
        labels = np.unique(np.concatenate([y_test, y_pred]))
        
        metrics = {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'confusion_matrix': confusion_matrix(y_test, y_pred, labels=labels).tolist(),
            'classification_report': classification_report(y_test, y_pred, labels=labels, target_names=target_names, output_dict=True)
        }
        
        self.metrics[model_name] = metrics
        
        logger.info("Evaluation complete", 
                   accuracy=accuracy, 
                   precision=precision, 
                   recall=recall, 
                   f1=f1)
        
        return metrics
    
    def save_models(self, prefix: str = ""):
        """Save all trained models"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for name, model in self.models.items():
            filename = f"{self.model_dir}/{prefix}{name}_{timestamp}.pkl"
            
            if isinstance(model, keras.Model):
                # Save Keras model
                keras_filename = filename.replace('.pkl', '.keras')
                model.save(keras_filename)
                logger.info("Saved Keras model", name=name, path=keras_filename)
            else:
                # Save sklearn model
                joblib.dump(model, filename)
                logger.info("Saved sklearn model", name=name, path=filename)
        
        # Save metrics
        metrics_file = f"{self.model_dir}/{prefix}metrics_{timestamp}.json"
        with open(metrics_file, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        
        logger.info("All models and metrics saved")
    
    def load_model(self, name: str, filepath: str):
        """Load a saved model"""
        if filepath.endswith('.keras') or filepath.endswith('.h5'):
            model = keras.models.load_model(filepath)
        else:
            model = joblib.load(filepath)
        
        self.models[name] = model
        logger.info("Model loaded", name=name, path=filepath)
        return model
    
    def get_feature_importance(self, model_name: str, feature_names: List[str]) -> Dict:
        """Get feature importance from tree-based models"""
        if model_name not in self.models:
            return {}
        
        model = self.models[model_name]
        
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            importance_dict = dict(zip(feature_names, importances))
            return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))
        
        return {}