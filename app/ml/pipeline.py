"""
Complete ML Pipeline for AIRS
Orchestrates data loading, preprocessing, training, and evaluation
"""

import asyncio
from typing import Dict, Optional, Any
from datetime import datetime
import structlog
import numpy as np

from app.ml.preprocessor import DionaeaPreprocessor, create_train_test_split
from app.ml.trainer import ModelTrainer

logger = structlog.get_logger("airs.ml.pipeline")


class TrainingPipeline:
    """
    End-to-end training pipeline for AIRS detection models.
    """
    
    def __init__(
        self,
        data_path: str,
        model_dir: str = "models",
        test_size: float = 0.2
    ):
        self.data_path = data_path
        self.model_dir = model_dir
        self.test_size = test_size
        
        self.preprocessor = DionaeaPreprocessor()
        self.trainer = ModelTrainer(model_dir=model_dir)
        
        self.results: Dict[str, Any] = {}
    
    async def run_full_pipeline(
        self,
        train_anomaly: bool = True,
        train_binary: bool = True,
        train_category: bool = True,
        use_neural_networks: bool = False
    ) -> Dict:
        """
        Execute complete training pipeline.
        
        Returns:
            Dictionary with all results and metrics
        """
        start_time = datetime.now()
        logger.info("Starting training pipeline", data_path=self.data_path)
        
        # ========== STEP 1: LOAD & PREPROCESS ==========
        logger.info("Step 1: Loading and preprocessing data")
        
        # Load data
        df = self.preprocessor.load_data(self.data_path)
        
        # Fit and transform
        X, y_binary, y_category, y_threat = self.preprocessor.fit_transform(df)
        
        # Create train/val/test split
        splits = create_train_test_split(X, y_binary, y_category, test_size=self.test_size)
        
        (X_train, X_val, X_test,
         y_bin_train, y_bin_val, y_bin_test,
         y_cat_train, y_cat_val, y_cat_test) = splits
        
        logger.info("Data split complete",
                   train_samples=len(X_train),
                   val_samples=len(X_val),
                   test_samples=len(X_test))
        
        # Save preprocessor
        self.preprocessor.save(f"{self.model_dir}/preprocessor.pkl")
        
        # ========== STEP 2: TRAIN ANOMALY DETECTOR ==========
        if train_anomaly:
            logger.info("Step 2: Training anomaly detector")
            
            # Train on normal samples only (label=0)
            normal_mask = (y_bin_train == 0).values
            X_normal = X_train[normal_mask]
            
            if len(X_normal) > 0:
                self.trainer.train_anomaly_detector(
                    X_normal,
                    contamination=0.1
                )
                
                # Evaluate on mixed test set
                # For anomaly detector, we need to convert predictions
                anomaly_metrics = self._evaluate_anomaly_detector(X_test, y_bin_test)
                self.results['anomaly_detector'] = anomaly_metrics
            else:
                logger.warning("No normal samples found for anomaly training")
        
        # ========== STEP 3: TRAIN BINARY CLASSIFIER ==========
        if train_binary:
            logger.info("Step 3: Training binary classifier")
            
            if use_neural_networks:
                binary_model = self.trainer.train_binary_classifier(
                    X_train, y_bin_train,
                    X_val, y_bin_val,
                    algorithm="neural_network"
                )
            else:
                binary_model = self.trainer.train_binary_classifier(
                    X_train, y_bin_train,
                    X_val, y_bin_val,
                    algorithm="random_forest"
                )
            
            # Evaluate
            binary_metrics = self.trainer.evaluate(
                'binary' if not use_neural_networks else 'binary_nn',
                X_test, y_bin_test,
                target_names=['normal', 'attack']
            )
            self.results['binary_classifier'] = binary_metrics
        
        # ========== STEP 4: TRAIN CATEGORY CLASSIFIER ==========
        if train_category:
            logger.info("Step 4: Training category classifier")
            
            # Only train on attack samples
            attack_mask = (y_bin_train == 1).values
            if attack_mask.sum() > 0:
                X_attacks = X_train[attack_mask]
                y_cat_attacks = y_cat_train[attack_mask]
                
                # Get category names from preprocessor
                category_names = None
                if 'attack_cat' in self.preprocessor.label_encoders:
                    le = self.preprocessor.label_encoders['attack_cat']
                    category_names = le.classes_.tolist()
                
                if use_neural_networks:
                    val_attack_mask = (y_bin_val == 1).values
                    category_model = self.trainer.train_category_classifier(
                        X_attacks, y_cat_attacks,
                        X_val[val_attack_mask], y_cat_val[val_attack_mask],
                        algorithm="neural_network"
                    )
                    model_key = 'category_nn'
                else:
                    val_attack_mask = (y_bin_val == 1).values
                    category_model = self.trainer.train_category_classifier(
                        X_attacks, y_cat_attacks,
                        X_val[val_attack_mask], y_cat_val[val_attack_mask],
                        algorithm="random_forest"
                    )
                    model_key = 'category'
                
                # Evaluate
                test_attack_mask = (y_bin_test == 1).values
                category_metrics = self.trainer.evaluate(
                    model_key,
                    X_test[test_attack_mask],
                    y_cat_test[test_attack_mask],
                    target_names=category_names
                )
                self.results['category_classifier'] = category_metrics
                
                # Feature importance
                if not use_neural_networks:
                    importance = self.trainer.get_feature_importance(
                        model_key,
                        self.preprocessor.feature_names
                    )
                    self.results['feature_importance'] = importance
            else:
                logger.warning("No attack samples found for category training")
        
        # ========== STEP 5: SAVE RESULTS ==========
        logger.info("Step 5: Saving models and results")
        
        self.trainer.save_models(prefix="airs_")
        
        # Calculate total time
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        self.results['training_metadata'] = {
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'data_path': self.data_path,
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'features': len(self.preprocessor.feature_names),
            'feature_names': self.preprocessor.feature_names
        }
        
        logger.info("Training pipeline complete", duration_seconds=duration)
        
        return self.results
    
    def _evaluate_anomaly_detector(self, X_test: Any, y_test: Any) -> Dict:
        """Special evaluation for anomaly detector"""
        model = self.trainer.models.get('anomaly')
        if model is None:
            return {}
        
        # Predict (-1 for anomaly, 1 for normal)
        predictions = model.predict(X_test)
        # Convert to binary (1 = anomaly/attack, 0 = normal)
        y_pred = np.where(predictions == -1, 1, 0)
        
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support
        
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
        
        return {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'note': 'Anomaly detector: unsupervised, trained on normal data only'
        }
    
    async def run_quick_train(
        self,
        sample_size: Optional[int] = None,
        algorithm: str = "random_forest"
    ) -> Dict:
        """
        Quick training on a sample for testing/development.
        """
        logger.info("Starting quick training", algorithm=algorithm, sample_size=sample_size)
        
        # Load data
        df = self.preprocessor.load_data(self.data_path)
        
        # Sample if requested
        if sample_size and len(df) > sample_size:
            df = df.sample(n=sample_size, random_state=42)
            logger.info("Sampled data", sample_size=sample_size)
        
        # Preprocess
        X, y_binary, y_category, y_threat = self.preprocessor.fit_transform(df)
        
        # Simple split
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
        )
        
        # Train only binary classifier
        self.trainer.train_binary_classifier(
            X_train, y_train,
            algorithm=algorithm
        )
        
        # Evaluate
        metrics = self.trainer.evaluate('binary', X_test, y_test)
        
        # Save
        self.trainer.save_models(prefix="quick_")
        self.preprocessor.save(f"{self.model_dir}/quick_preprocessor.pkl")
        
        self.results = {
            'binary_classifier': metrics,
            'metadata': {
                'algorithm': algorithm,
                'sample_size': len(df),
                'features': len(self.preprocessor.feature_names)
            }
        }
        
        return self.results


# Convenience function for CLI/script usage
async def train_airs_models(
    data_path: str,
    model_dir: str = "models",
    use_neural_networks: bool = False,
    quick_mode: bool = False
) -> Dict:
    """
    Main entry point for training AIRS models.
    
    Args:
        data_path: Path to Dionaea CSV file
        model_dir: Directory to save models
        use_neural_networks: Whether to use neural networks (slower but potentially better)
        quick_mode: If True, use small sample for quick testing
    
    Returns:
        Training results and metrics
    """
    pipeline = TrainingPipeline(
        data_path=data_path,
        model_dir=model_dir
    )
    
    if quick_mode:
        return await pipeline.run_quick_train(sample_size=10000)
    else:
        return await pipeline.run_full_pipeline(
            train_anomaly=True,
            train_binary=True,
            train_category=True,
            use_neural_networks=use_neural_networks
        )