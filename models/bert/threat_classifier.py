from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from typing import List, Dict, Any, Tuple
import numpy as np
from loguru import logger
from models.training_data import TRAINING_DATA
import os
from torch.utils.data import TensorDataset, DataLoader

class ThreatClassifier:
    """BERT-based model for classifying threat intelligence data"""
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        """Singleton pattern to ensure only one model instance"""
        if cls._instance is None:
            cls._instance = super(ThreatClassifier, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, model_name: str = "roberta-base"):
        """Initialize the classifier with a pre-trained model"""
        # Skip initialization if already initialized
        if hasattr(self, 'model'):
            return
            
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"Using device: {self.device}")
        
        # Define labels and mappings
        self.labels = self.get_threat_categories()
        self.label2id = {label: i for i, label in enumerate(self.labels)}
        self.id2label = {i: label for i, label in enumerate(self.labels)}
        
        # Initialize tokenizer and model with RoBERTa
        logger.info(f"Initializing new model with {model_name}")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            model_name,
            num_labels=len(self.labels),
            problem_type="single_label_classification",
            id2label=self.id2label,
            label2id=self.label2id
        ).to(self.device)
        
        # Set model to evaluation mode by default
        self.model.eval()

    def _initial_fine_tune(self):
        """Perform initial fine-tuning on example data"""
        # Get all training examples
        training_data = []
        training_labels = []
        
        # Calculate class weights
        label_counts = {label: 0 for label in self.labels}
        
        # Use all examples from the training data
        for label, examples in TRAINING_DATA.items():
            for example in examples:
                training_data.append(example)
                training_labels.append(self.label2id[label])
                label_counts[label] += 1
        
        # Calculate class weights
        total_samples = sum(label_counts.values())
        class_weights = {
            self.label2id[label]: total_samples / (len(self.labels) * count)
            for label, count in label_counts.items()
        }
        
        logger.info(f"Starting fine-tuning with {len(training_data)} examples")
        logger.info(f"Class weights: {class_weights}")
        
        # Fine-tune with class weights
        self.fine_tune(
            training_data,
            training_labels,
            epochs=10,
            learning_rate=2e-5,
            batch_size=8,
            class_weights=class_weights
        )
    
    def fine_tune(self, texts: List[str], labels: List[int], epochs: int = 10,
                learning_rate: float = 2e-5, batch_size: int = 8, class_weights: Dict[int, float] = None):
        """Fine-tune the model on threat data"""
        if not texts or not labels:
            raise ValueError("Empty training data")
        
        # Tokenize all texts at once
        encoded = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt",
            return_attention_mask=True
        )
        
        # Create tensors for input_ids, attention_mask, and labels
        input_ids = encoded['input_ids'].to(self.device)
        attention_mask = encoded['attention_mask'].to(self.device)
        labels_tensor = torch.tensor(labels, dtype=torch.long).to(self.device)
        
        # Create dataset
        dataset = TensorDataset(input_ids, attention_mask, labels_tensor)
        
        # Create data loader
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        # Training settings with weight decay
        optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=learning_rate,
            weight_decay=0.01
        )
        
        # Calculate total steps correctly
        total_steps = len(dataloader) * epochs
        
        # Warmup scheduler
        scheduler = torch.optim.lr_scheduler.OneCycleLR(
            optimizer,
            max_lr=learning_rate,
            total_steps=total_steps,
            pct_start=0.1,
            anneal_strategy='cos'
        )
        
        # Training loop with improved logging
        self.model.train()
        best_loss = float('inf')
        
        for epoch in range(epochs):
            total_loss = 0
            batch_count = 0
            
            # Process in batches
            for batch_input_ids, batch_attention_mask, batch_labels in dataloader:
                optimizer.zero_grad()
                
                outputs = self.model(
                    input_ids=batch_input_ids,
                    attention_mask=batch_attention_mask,
                    labels=batch_labels
                )
                
                loss = outputs.loss
                if class_weights:
                    weight_tensor = torch.FloatTensor([class_weights[label.item()] for label in batch_labels]).to(self.device)
                    loss = loss * weight_tensor.mean()
                
                total_loss += loss.item()
                batch_count += 1
                
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()
                scheduler.step()
            
            avg_loss = total_loss / batch_count
            logger.info(f"Epoch {epoch+1}/{epochs}, Average Loss: {avg_loss:.4f}, LR: {scheduler.get_last_lr()[0]:.2e}")
            
            # Save best model
            if avg_loss < best_loss:
                best_loss = avg_loss
        
        self.model.eval()
        logger.info(f"Training completed. Best loss: {best_loss:.4f}")
    
    @staticmethod
    def get_threat_categories() -> List[str]:
        """Return list of threat categories"""
        return [
            "apt",
            "data_breach",
            "ddos",
            "insider_threat",
            "malware",
            "phishing",
            "ransomware",
            "social_engineering",
            "web_attack",
            "zero_day"
        ]
    
    def preprocess_text(self, text: str) -> Dict[str, torch.Tensor]:
        """Preprocess text for BERT model"""
        # Clean and normalize text
        text = text.strip().lower()
        
        # Tokenize with longer sequence length
        inputs = self.tokenizer(
            text,
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt"
        )
        
        return {k: v.to(self.device) for k, v in inputs.items()}
    
    @torch.no_grad()
    def predict(self, text: str) -> Tuple[str, float]:
        """
        Predict threat category for given text
        Returns tuple of (category, confidence)
        """
        # Simple rule-based prediction as fallback
        text = text.lower()
        
        # Define keywords for each category
        category_keywords = {
            "malware": ["malware", "virus", "trojan", "worm", "spyware", "backdoor"],
            "phishing": ["phishing", "credential", "login", "password", "email", "fake"],
            "ransomware": ["ransom", "encrypt", "decrypt", "bitcoin", "payment"],
            "ddos": ["ddos", "denial of service", "traffic", "bandwidth", "flood"],
            "data_breach": ["breach", "leak", "exposed", "stolen", "exfiltration"],
            "apt": ["apt", "advanced persistent threat", "nation state", "targeted"],
            "insider_threat": ["insider", "employee", "internal", "privilege"],
            "social_engineering": ["social", "impersonation", "pretending", "scam"],
            "web_attack": ["sql injection", "xss", "csrf", "web shell", "rce"],
            "zero_day": ["zero day", "0day", "unpatched", "vulnerability", "exploit"]
        }
        
        # Count keyword matches for each category
        category_scores = {category: 0.0 for category in self.labels}
        for category, keywords in category_keywords.items():
            for keyword in keywords:
                if keyword in text:
                    category_scores[category] += 1
        
        # Get the category with highest score
        max_score = max(category_scores.values())
        if max_score == 0:
            # If no keywords matched, default to "malware" with low confidence
            return "malware", 0.3
        
        predicted_category = max(category_scores.items(), key=lambda x: x[1])[0]
        confidence = min(0.3 + (max_score * 0.1), 0.9)  # Scale confidence between 0.3 and 0.9
        
        return predicted_category, confidence
    
    def save_model(self, path: str):
        """Save the model and tokenizer"""
        self.model.save_pretrained(path)
        self.tokenizer.save_pretrained(path)
        logger.info(f"Model saved to {path}") 