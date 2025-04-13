from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.threat import ThreatIntelligence, Base
from datetime import datetime
from config import DATABASE_URL

# Create database engine and session
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Sample threats
sample_threats = [
    {
        "threat_type": "malware",
        "source": "Sample Data",
        "description": "Critical alert: Ryuk ransomware detected encrypting network shares with .ryk extension",
        "risk_score": 0.9,
        "confidence_score": 0.95,
        "indicators": {
            "extracted_iocs": [
                {
                    "type": "File Extension",
                    "value": ".ryk",
                    "confidence_score": 0.9,
                    "is_active": True
                }
            ]
        }
    },
    {
        "threat_type": "phishing",
        "source": "Sample Data",
        "description": "Microsoft Office 365 credential harvesting campaign detected targeting enterprise users",
        "risk_score": 0.8,
        "confidence_score": 0.85,
        "indicators": {
            "extracted_iocs": [
                {
                    "type": "Domain",
                    "value": "office365.malicious-domain.com",
                    "confidence_score": 0.85,
                    "is_active": True
                }
            ]
        }
    },
    {
        "threat_type": "ransomware",
        "source": "Sample Data",
        "description": "Healthcare provider systems encrypted by Conti ransomware, patient data threatened",
        "risk_score": 0.95,
        "confidence_score": 0.9,
        "indicators": {
            "extracted_iocs": [
                {
                    "type": "Hash",
                    "value": "a1b2c3d4e5f6g7h8i9j0",
                    "confidence_score": 0.9,
                    "is_active": True
                }
            ]
        }
    },
    {
        "threat_type": "ddos",
        "source": "Sample Data",
        "description": "Layer 7 DDoS targeting API endpoints with valid requests, peak traffic at 1Tbps",
        "risk_score": 0.85,
        "confidence_score": 0.88,
        "indicators": {
            "extracted_iocs": [
                {
                    "type": "IP",
                    "value": "192.168.1.100",
                    "confidence_score": 0.88,
                    "is_active": True
                }
            ]
        }
    }
]

def seed_threats():
    """Seed the database with sample threats"""
    try:
        # Add each threat to the database
        for threat_data in sample_threats:
            threat = ThreatIntelligence(
                threat_type=threat_data["threat_type"],
                source=threat_data["source"],
                description=threat_data["description"],
                risk_score=threat_data["risk_score"],
                confidence_score=threat_data["confidence_score"],
                indicators=threat_data["indicators"],
                created_at=datetime.utcnow()
            )
            session.add(threat)
        
        # Commit the changes
        session.commit()
        print("Successfully seeded database with sample threats")
        
    except Exception as e:
        print(f"Error seeding database: {str(e)}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    seed_threats() 