import json
import os
from typing import List, Dict, Tuple, Optional
import pandas as pd
from sklearn.model_selection import train_test_split
from loguru import logger
import re

class ThreatDataManager:
    """Manager for handling threat intelligence training data"""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.training_dir = os.path.join(data_dir, "training")
        self.processed_dir = os.path.join(data_dir, "processed")
        
        # Create directories if they don't exist
        os.makedirs(self.training_dir, exist_ok=True)
        os.makedirs(self.processed_dir, exist_ok=True)
        
        # Initialize logger
        logger.add(
            os.path.join(data_dir, "data_manager.log"),
            rotation="500 MB",
            retention="10 days",
            level="INFO"
        )
    
    def validate_text(self, text: str) -> Optional[str]:
        """Validate and clean text data with enhanced preprocessing"""
        if not isinstance(text, str):
            return None
            
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text.strip())
        
        # Check minimum length (e.g., 10 characters)
        if len(text) < 10:
            return None
            
        # Check maximum length (e.g., 1000 characters)
        if len(text) > 1000:
            text = text[:1000]
            
        # Enhanced text cleaning
        text = re.sub(r'[^\w\s.,!?-]', '', text)  # Remove special characters except basic punctuation
        text = re.sub(r'\s+', ' ', text)  # Normalize whitespace
        text = text.lower()  # Convert to lowercase
        
        return text
    
    def augment_text(self, text: str) -> List[str]:
        """Apply data augmentation techniques to text"""
        augmented_texts = []
        
        # Original text
        augmented_texts.append(text)
        
        # Synonym replacement
        try:
            from nltk.corpus import wordnet
            import nltk
            nltk.download('wordnet', quiet=True)
            
            words = text.split()
            for i, word in enumerate(words):
                synonyms = wordnet.synsets(word)
                if synonyms:
                    for syn in synonyms[:2]:  # Use up to 2 synonyms per word
                        for lemma in syn.lemmas():
                            if lemma.name() != word:
                                new_words = words.copy()
                                new_words[i] = lemma.name()
                                augmented_texts.append(' '.join(new_words))
        except Exception as e:
            logger.warning(f"Error in synonym replacement: {str(e)}")
        
        # Back-translation (if available)
        try:
            from googletrans import Translator
            translator = Translator()
            
            # Translate to intermediate language and back
            intermediate_langs = ['es', 'fr', 'de']
            for lang in intermediate_langs:
                try:
                    translated = translator.translate(text, dest=lang)
                    back_translated = translator.translate(translated.text, dest='en')
                    if back_translated.text != text:
                        augmented_texts.append(back_translated.text)
                except Exception as e:
                    logger.warning(f"Error in back-translation to {lang}: {str(e)}")
        except Exception as e:
            logger.warning(f"Error in back-translation setup: {str(e)}")
        
        # Add domain-specific augmentations
        threat_patterns = {
            r'ip address': ['IP address', 'IP', 'internet protocol address'],
            r'domain': ['domain name', 'DNS record', 'hostname'],
            r'hash': ['hash value', 'checksum', 'digest'],
            r'url': ['URL', 'web address', 'link'],
            r'port': ['port number', 'TCP port', 'UDP port']
        }
        
        for pattern, replacements in threat_patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                for replacement in replacements:
                    new_text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
                    if new_text != text:
                        augmented_texts.append(new_text)
        
        return list(set(augmented_texts))  # Remove duplicates
    
    def add_training_data(self, category: str, texts: List[str]) -> Dict[str, int]:
        """
        Add new training data for a specific category with augmentation
        Returns statistics about added data
        """
        if not category or not isinstance(category, str):
            raise ValueError("Invalid category")
            
        if not texts or not isinstance(texts, list):
            raise ValueError("texts must be a non-empty list of strings")
        
        stats = {"total": len(texts), "added": 0, "invalid": 0, "augmented": 0}
        file_path = os.path.join(self.training_dir, f"{category}.jsonl")
        
        try:
            # Clear existing file to avoid duplicates
            with open(file_path, "w") as f:
                for text in texts:
                    # Validate and clean text
                    cleaned_text = self.validate_text(text)
                    if cleaned_text is None:
                        stats["invalid"] += 1
                        continue
                    
                    # Add original text
                    entry = {
                        "text": cleaned_text,
                        "category": category,
                        "augmented": False
                    }
                    f.write(json.dumps(entry) + "\n")
                    stats["added"] += 1
                    
                    # Add augmented versions
                    augmented_texts = self.augment_text(cleaned_text)
                    for aug_text in augmented_texts:
                        if aug_text != cleaned_text:
                            aug_entry = {
                                "text": aug_text,
                                "category": category,
                                "augmented": True
                            }
                            f.write(json.dumps(aug_entry) + "\n")
                            stats["augmented"] += 1
                    
            logger.info(f"Added {stats['added']} entries and {stats['augmented']} augmented entries "
                       f"to {category} category ({stats['invalid']} invalid entries skipped)")
            return stats
            
        except Exception as e:
            logger.error(f"Error adding training data: {str(e)}")
            raise
    
    def load_training_data(self) -> Tuple[List[str], List[int]]:
        """Load and process all training data"""
        texts = []
        labels = []
        categories = {}  # Map category names to indices
        
        try:
            # Get all training files
            training_files = sorted([f for f in os.listdir(self.training_dir)
                                  if f.endswith(".jsonl")])
            
            if not training_files:
                logger.warning("No training files found")
                return [], []
            
            for file_name in training_files:
                category = file_name[:-6]  # Remove .jsonl extension
                if category not in categories:
                    categories[category] = len(categories)
                
                file_path = os.path.join(self.training_dir, file_name)
                valid_entries = 0
                
                with open(file_path, "r") as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            if "text" in entry and "category" in entry:
                                cleaned_text = self.validate_text(entry["text"])
                                if cleaned_text is not None:
                                    texts.append(cleaned_text)
                                    labels.append(categories[category])
                                    valid_entries += 1
                        except json.JSONDecodeError:
                            logger.warning(f"Invalid JSON in {file_name}")
                            continue
                
                logger.info(f"Loaded {valid_entries} valid entries from {file_name}")
            
            # Save category mapping
            if categories:
                with open(os.path.join(self.processed_dir, "categories.json"), "w") as f:
                    json.dump(categories, f, indent=2)
                logger.info(f"Saved category mapping with {len(categories)} categories")
            
            return texts, labels
            
        except Exception as e:
            logger.error(f"Error loading training data: {str(e)}")
            raise
    
    def prepare_training_data(self, test_size: float = 0.2, random_state: int = 42) -> Dict:
        """Prepare data for training and testing"""
        texts, labels = self.load_training_data()
        
        if not texts:
            raise ValueError("No valid training data found")
        
        if len(set(labels)) < 2:
            raise ValueError("At least two categories with valid data are required")
        
        try:
            # Split into train and test sets
            X_train, X_test, y_train, y_test = train_test_split(
                texts, labels,
                test_size=test_size,
                random_state=random_state,
                stratify=labels
            )
            
            logger.info(f"Split data into {len(X_train)} training and {len(X_test)} test samples")
            
            return {
                "train": {
                    "texts": X_train,
                    "labels": y_train
                },
                "test": {
                    "texts": X_test,
                    "labels": y_test
                }
            }
        except Exception as e:
            logger.error(f"Error preparing training data: {str(e)}")
            raise
    
    def get_data_stats(self) -> Dict:
        """Get statistics about the training data"""
        stats = {
            "total_samples": 0,
            "categories": {},
            "avg_text_length": 0,
            "num_files": 0
        }
        
        try:
            total_length = 0
            for file_name in os.listdir(self.training_dir):
                if file_name.endswith(".jsonl"):
                    category = file_name[:-6]
                    file_path = os.path.join(self.training_dir, file_name)
                    
                    # Count valid entries and calculate text lengths
                    valid_entries = 0
                    category_text_length = 0
                    
                    with open(file_path, "r") as f:
                        for line in f:
                            try:
                                entry = json.loads(line)
                                if "text" in entry:
                                    text = entry["text"]
                                    if self.validate_text(text):
                                        valid_entries += 1
                                        category_text_length += len(text)
                            except json.JSONDecodeError:
                                continue
                    
                    if valid_entries > 0:
                        stats["categories"][category] = {
                            "count": valid_entries,
                            "avg_length": category_text_length / valid_entries
                        }
                        stats["total_samples"] += valid_entries
                        total_length += category_text_length
                        stats["num_files"] += 1
            
            if stats["total_samples"] > 0:
                stats["avg_text_length"] = total_length / stats["total_samples"]
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting data stats: {str(e)}")
            raise
    
    def add_sample_data(self):
        """Add sample training data for testing"""
        sample_data = {
            "malware": [
                "A new strain of ransomware has been detected encrypting files with .locked extension",
                "The trojan downloads additional malicious payloads from command and control servers",
                "The malware spreads through infected USB drives and network shares",
                "Advanced persistent threat group deploys custom malware targeting industrial systems",
                "New variant of banking trojan steals cryptocurrency wallet credentials",
                "Emotet malware campaign targets corporate networks with new evasion techniques",
                "Cryptomining malware discovered in compromised container images",
                "Sophisticated backdoor malware uses DNS tunneling for command and control",
                "New fileless malware variant evades traditional antivirus detection",
                "Mobile banking trojan targets financial apps with overlay attacks"
            ],
            "phishing": [
                "Attackers are sending fake login pages mimicking Microsoft Office 365",
                "The phishing campaign targets banking credentials through spoofed emails",
                "Users receive fake package delivery notifications with malicious attachments",
                "Sophisticated spear-phishing campaign targeting C-level executives",
                "Mass phishing attack impersonates government tax authorities",
                "Phishing emails exploit COVID-19 vaccine appointment themes",
                "Business email compromise attack targets finance department employees",
                "Credential harvesting campaign uses fake password reset notifications",
                "Phishing attack leverages Google Docs comments for distribution",
                "Social media phishing campaign exploits trending topics"
            ],
            "ddos": [
                "The botnet launched a massive DDoS attack reaching 1Tbps",
                "Multiple servers experienced downtime due to UDP flood attacks",
                "The DDoS campaign targeted financial institutions' APIs",
                "Distributed denial of service attack disrupts cloud service provider",
                "New IoT botnet orchestrates volumetric DDoS attacks",
                "DDoS attack combines multiple protocols for amplification",
                "Gaming servers targeted by layer 7 DDoS attacks",
                "Ransom DDoS campaign threatens organizations with sustained attacks",
                "DDoS attack exploits memcached servers for amplification",
                "Critical infrastructure targeted by coordinated DDoS campaign"
            ],
            "zero_day": [
                "Critical zero-day vulnerability discovered in widely used networking equipment",
                "Attackers actively exploiting unpatched zero-day in popular web browser",
                "Zero-day exploit chain targets mobile operating system security features",
                "Security researchers identify zero-day affecting multiple cloud platforms",
                "Nation-state actors leveraging zero-day vulnerabilities in targeted attacks",
                "Zero-day vulnerability in VPN software enables remote code execution",
                "Previously unknown zero-day exploited in supply chain attack",
                "Emergency patch released for actively exploited zero-day vulnerability",
                "Zero-day exploit broker announces bounty for messaging app vulnerabilities",
                "Researchers discover zero-day affecting industrial control systems"
            ],
            "apt": [
                "Advanced persistent threat group targets defense contractors with spear-phishing",
                "APT campaign uses custom malware to exfiltrate sensitive data",
                "State-sponsored threat actors compromise telecommunications infrastructure",
                "APT group leverages supply chain attack for initial access",
                "Advanced threat actors exploit zero-day vulnerabilities in targeted campaign",
                "APT group targets energy sector with specialized malware",
                "Nation-state hackers compromise satellite communications",
                "Advanced persistent threat conducts cyber espionage against research institutions",
                "APT campaign targets intellectual property in manufacturing sector",
                "State-sponsored actors deploy custom backdoors in government networks"
            ],
            "web_attack": [
                "SQL injection attack compromises e-commerce database",
                "Cross-site scripting vulnerability exploited on popular web platform",
                "Web application firewall bypass enables remote code execution",
                "Attackers exploit path traversal vulnerability in web server",
                "XML external entity attack targets enterprise applications",
                "Web shell uploaded through vulnerable file upload function",
                "Server-side request forgery attack enables cloud metadata access",
                "Remote code execution achieved through deserialization vulnerability",
                "Web cache poisoning attack affects multiple CDN users",
                "Authentication bypass discovered in web application framework"
            ],
            "insider_threat": [
                "Disgruntled employee exfiltrates sensitive customer data",
                "Privileged user account compromised by social engineering",
                "Insider sells access credentials on dark web marketplace",
                "Employee installs unauthorized software leading to breach",
                "System administrator abuses privileges for cryptocurrency mining",
                "Contractor exposes confidential documents through misconfiguration",
                "Insider threat actor deploys ransomware in corporate network",
                "Terminated employee retains access to critical systems",
                "Malicious insider modifies financial transaction records",
                "Privileged account abuse leads to intellectual property theft"
            ],
            "data_breach": [
                "Healthcare provider reports breach affecting patient records",
                "Retail chain discovers unauthorized access to payment systems",
                "Educational institution exposes student data through misconfiguration",
                "Cloud storage bucket leaks sensitive corporate documents",
                "Financial services firm reports breach of customer accounts",
                "Third-party vendor compromise leads to data exposure",
                "Hotel chain discovers unauthorized access to guest records",
                "Technology company reports breach of user credentials",
                "Government agency exposes citizen data through unsecured database",
                "Social media platform reports unauthorized access to user accounts"
            ],
            "ransomware": [
                "Ransomware group targets healthcare providers with double extortion",
                "Manufacturing plant operations disrupted by ransomware attack",
                "Educational institution hit by ransomware demanding cryptocurrency",
                "Ransomware attack encrypts backups using stolen credentials",
                "Local government systems locked by targeted ransomware attack",
                "New ransomware variant includes worm-like spreading capabilities",
                "Managed service provider's clients affected by ransomware attack",
                "Ransomware operators threaten to leak stolen corporate data",
                "Critical infrastructure targeted by ransomware campaign",
                "Supply chain compromise leads to widespread ransomware infection"
            ],
            "social_engineering": [
                "Business email compromise scam targets financial transactions",
                "Vishing attack impersonates technical support services",
                "Social engineering campaign exploits work-from-home scenarios",
                "Attackers use deepfake technology for executive impersonation",
                "QR code phishing campaign targets mobile users",
                "Social media platform used for targeted reconnaissance",
                "Smishing attack exploits package delivery notifications",
                "Impersonation attack targets human resources departments",
                "Social engineering enables unauthorized wire transfer",
                "Attackers exploit trust relationships between organizations"
            ]
        }
        
        total_stats = {"total": 0, "added": 0, "invalid": 0}
        for category, texts in sample_data.items():
            stats = self.add_training_data(category, texts)
            for key in total_stats:
                total_stats[key] += stats[key]
        
        logger.info(f"Added {total_stats['added']} sample entries across {len(sample_data)} categories") 