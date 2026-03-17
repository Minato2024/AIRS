#!/usr/bin/env python3
"""
Training script for AIRS models.
Run this to train detection models on Dionaea honeypot data.
"""

import asyncio
import argparse
import sys
from pathlib import Path

# Add app to path
sys.path.insert(0, str(Path(__file__).parent))

from app.ml.pipeline import train_airs_models
import structlog

# Configure logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.dev.ConsoleRenderer()
    ]
)
logger = structlog.get_logger("airs.train")


def main():
    parser = argparse.ArgumentParser(description="Train AIRS detection models")
    parser.add_argument(
        "data_path",
        help="Path to Dionaea CSV dataset"
    )
    parser.add_argument(
        "--model-dir",
        default="models",
        help="Directory to save trained models"
    )
    parser.add_argument(
        "--neural",
        action="store_true",
        help="Use neural networks (slower but may be more accurate)"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick training on sample (for testing)"
    )
    parser.add_argument(
        "--no-anomaly",
        action="store_true",
        help="Skip anomaly detector training"
    )
    parser.add_argument(
        "--no-category",
        action="store_true",
        help="Skip category classifier training"
    )
    
    args = parser.parse_args()
    
    logger.info(
        "Starting training",
        data_path=args.data_path,
        model_dir=args.model_dir,
        neural=args.neural,
        quick=args.quick
    )
    
    # Run training
    results = asyncio.run(train_airs_models(
        data_path=args.data_path,
        model_dir=args.model_dir,
        use_neural_networks=args.neural,
        quick_mode=args.quick
    ))
    
    # Print summary
    print("\n" + "="*50)
    print("TRAINING COMPLETE")
    print("="*50)
    
    if 'binary_classifier' in results:
        metrics = results['binary_classifier']
        print(f"\nBinary Classifier:")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1 Score:  {metrics['f1_score']:.4f}")
    
    if 'category_classifier' in results:
        metrics = results['category_classifier']
        print(f"\nCategory Classifier:")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  F1 Score:  {metrics['f1_score']:.4f}")
    
    if 'anomaly_detector' in results:
        metrics = results['anomaly_detector']
        print(f"\nAnomaly Detector:")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  F1 Score:  {metrics['f1_score']:.4f}")
    
    if 'feature_importance' in results:
        print(f"\nTop 10 Important Features:")
        for i, (feature, importance) in enumerate(list(results['feature_importance'].items())[:10]):
            print(f"  {i+1}. {feature}: {importance:.4f}")
    
    print(f"\nModels saved to: {args.model_dir}")
    print("="*50)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())