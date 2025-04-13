import os
import sys
import json
from datetime import datetime
import torch
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import classification_report
from typing import Dict, Any
from loguru import logger

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from models.bert.data_manager import ThreatDataManager
from models.bert.threat_classifier import ThreatClassifier

def train_model(
    data_dir: str = "data",
    model_dir: str = "models/saved",
    batch_size: int = 8,
    epochs: int = 20,
    learning_rate: float = 1e-5,
    max_length: int = 512,
    device: str = None,
    model_name: str = "roberta-base",
    test_size: float = 0.2,
    early_stopping_patience: int = 7,
    warmup_steps: int = 200,
    n_folds: int = 5,
    gradient_accumulation_steps: int = 4
) -> Dict[str, Any]:
    """Train the threat classification model with enhanced techniques"""
    
    try:
        # Ensure directories exist
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(model_dir, exist_ok=True)
        os.makedirs("logs", exist_ok=True)
        
        # Initialize data manager and load data
        data_manager = ThreatDataManager(data_dir)
        
        # Add sample data if no data exists
        stats = data_manager.get_data_stats()
        if stats["total_samples"] == 0:
            logger.info("No training data found. Adding sample data...")
            data_manager.add_sample_data()
            stats = data_manager.get_data_stats()
            logger.info(f"Added sample data. Total samples: {stats['total_samples']}")
        
        # Prepare data
        data = data_manager.prepare_training_data(test_size=test_size)
        
        # Initialize model
        classifier = ThreatClassifier(model_name=model_name)
        device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"Using device: {device}")
        
        # Train the model using the classifier's fine_tune method
        try:
            classifier.fine_tune(
                texts=data["train"]["texts"],
                labels=data["train"]["labels"],
                epochs=epochs,
                learning_rate=learning_rate,
                batch_size=batch_size
            )
        except Exception as e:
            logger.error(f"Error in training: {str(e)}")
            raise
        
        # Save the model
        try:
            os.makedirs(model_dir, exist_ok=True)
            classifier.save_model(model_dir)
            logger.info(f"Model saved to {model_dir}")
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
            raise
        
        return {
            "status": "success",
            "model_path": model_dir
        }
        
    except Exception as e:
        logger.error(f"Training failed: {str(e)}")
        raise

if __name__ == "__main__":
    # Configure logging
    logger.add(
        "logs/training.log",
        rotation="500 MB",
        retention="10 days",
        level="INFO"
    )
    
    try:
        # Train the model
        results = train_model()
        
        # Print results
        logger.info("Training completed!")
        logger.info(f"Model saved to: {results['model_path']}")
    except Exception as e:
        logger.error(f"Training failed: {str(e)}")
        sys.exit(1) 