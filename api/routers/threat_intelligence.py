from fastapi import APIRouter, Depends, HTTPException, Query, Body, UploadFile, File
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from typing import List, Optional
from datetime import datetime, timedelta
from models.threat import ThreatIntelligence, ThreatActor, IOC
from database.config import get_db
from models.bert.threat_classifier import ThreatClassifier
from collectors.feeds.alienvault_collector import AlienVaultCollector
from collectors.feeds.virustotal_collector import VirusTotalCollector
from pydantic import BaseModel
import os
from loguru import logger
import re
from fastapi.responses import JSONResponse
import PyPDF2
import io

router = APIRouter(prefix="/api/v1/threat-intelligence", tags=["threat-intelligence"])

# Initialize threat classifier
classifier = ThreatClassifier()

# Initialize collectors
alienvault_collector = AlienVaultCollector({
    "api_key": os.getenv("ALIENVAULT_API_KEY")
})

virustotal_collector = VirusTotalCollector({
    "api_key": os.getenv("VIRUSTOTAL_API_KEY")
})

class ThreatIntelligenceResponse(BaseModel):
    id: int
    threat_type: str
    source: str
    description: str
    risk_score: float
    confidence_score: float
    created_at: datetime
    indicators: List[dict] = []

class ThreatAnalysisRequest(BaseModel):
    text: str

@router.get("/threats")
async def get_threats(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    threat_type: Optional[str] = None,
    min_risk_score: Optional[float] = None
):
    """Get a list of threats with optional filtering"""
    try:
        # Build base query
        query = db.query(ThreatIntelligence)
        
        # Apply filters if provided
        if threat_type:
            query = query.filter(ThreatIntelligence.threat_type == threat_type)
        if min_risk_score is not None:
            query = query.filter(ThreatIntelligence.risk_score >= min_risk_score)
        
        # Get total count before pagination
        total_count = query.count()
        
        # Get paginated results
        threats = query.order_by(ThreatIntelligence.created_at.desc()).offset(skip).limit(limit).all()
        
        # Format response
        formatted_threats = []
        for threat in threats:
            # Handle indicators field
            indicators_list = []
            if threat.indicators:
                if isinstance(threat.indicators, dict) and 'extracted_iocs' in threat.indicators:
                    indicators_list = threat.indicators['extracted_iocs']
                elif isinstance(threat.indicators, list):
                    indicators_list = threat.indicators
            
            formatted_threat = {
                "id": threat.id,
                "threat_type": threat.threat_type,
                "source": threat.source,
                "description": threat.description,
                "risk_score": threat.risk_score,
                "confidence_score": threat.confidence_score,
                "created_at": threat.created_at.isoformat() if threat.created_at else None,
                "indicators": indicators_list
            }
            formatted_threats.append(formatted_threat)
        
        # Create response with headers
        response = JSONResponse(content=formatted_threats)
        response.headers["Access-Control-Expose-Headers"] = "X-Total-Count"
        response.headers["X-Total-Count"] = str(total_count)
        return response
        
    except Exception as e:
        logger.error(f"Error getting threats: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving threats")

@router.get("/threats/{threat_id}", response_model=ThreatIntelligenceResponse)
async def get_threat(threat_id: int, db: Session = Depends(get_db)):
    """Get detailed information about a specific threat"""
    try:
        threat = db.query(ThreatIntelligence).filter(ThreatIntelligence.id == threat_id).first()
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        # Handle indicators field
        indicators_list = []
        if threat.indicators:
            if isinstance(threat.indicators, dict) and 'extracted_iocs' in threat.indicators:
                indicators_list = threat.indicators['extracted_iocs']
            elif isinstance(threat.indicators, list):
                indicators_list = threat.indicators
        
        # Format response
        formatted_threat = {
            "id": threat.id,
            "threat_type": threat.threat_type,
            "source": threat.source,
            "description": threat.description,
            "risk_score": threat.risk_score,
            "confidence_score": threat.confidence_score,
            "created_at": threat.created_at,
            "indicators": indicators_list
        }
        
        return formatted_threat
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        logger.error(f"Error getting threat details: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving threat details")

def extract_iocs(text: str) -> List[dict]:
    """Extract Indicators of Compromise from text"""
    iocs = []
    
    # IP address pattern
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, text)
    for ip in ips:
        iocs.append({
            "type": "IP",
            "value": ip,
            "confidence_score": 0.9,
            "is_active": True
        })
    
    # Domain pattern
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domains = re.findall(domain_pattern, text)
    for domain in domains:
        if not any(ip in domain for ip in ips):  # Avoid duplicate matches with IPs
            iocs.append({
                "type": "Domain",
                "value": domain,
                "confidence_score": 0.85,
                "is_active": True
            })
    
    # Hash patterns (MD5, SHA1, SHA256)
    hash_patterns = {
        "MD5": r'\b[a-fA-F0-9]{32}\b',
        "SHA1": r'\b[a-fA-F0-9]{40}\b',
        "SHA256": r'\b[a-fA-F0-9]{64}\b'
    }
    
    for hash_type, pattern in hash_patterns.items():
        hashes = re.findall(pattern, text)
        for hash_value in hashes:
            iocs.append({
                "type": hash_type,
                "value": hash_value,
                "confidence_score": 0.95,
                "is_active": True
            })
    
    return iocs

def get_mitre_techniques(category: str) -> List[dict]:
    """Get relevant MITRE ATT&CK techniques based on threat category"""
    # This is a simplified mapping. In a production environment,
    # you would want to use the official MITRE ATT&CK API or database
    technique_mapping = {
        "malware": [
            {
                "id": "T1204",
                "name": "User Execution",
                "description": "Adversaries may rely upon specific actions by a user in order to gain execution."
            },
            {
                "id": "T1055",
                "name": "Process Injection",
                "description": "Adversaries may inject code into processes to evade process-based defenses and potentially elevate privileges."
            }
        ],
        "phishing": [
            {
                "id": "T1566",
                "name": "Phishing",
                "description": "Adversaries may send phishing messages to gain access to victim systems."
            }
        ],
        "ransomware": [
            {
                "id": "T1486",
                "name": "Data Encrypted for Impact",
                "description": "Adversaries may encrypt data on target systems to interrupt availability to system and network resources."
            }
        ],
        "ddos": [
            {
                "id": "T1498",
                "name": "Network Denial of Service",
                "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources."
            }
        ]
    }
    
    return technique_mapping.get(category, [])

@router.post("/analyze")
async def analyze_threat(
    request: ThreatAnalysisRequest,
    db: Session = Depends(get_db)
):
    """Analyze threat description and extract IOCs"""
    try:
        if not request.text.strip():
            raise HTTPException(status_code=400, detail="Text to analyze is required")

        logger.info("Starting threat analysis")
        
        # Get threat category and confidence from the classifier
        try:
            category, confidence = classifier.predict(request.text)
            logger.info(f"Predicted category: {category} with confidence: {confidence}")
        except Exception as e:
            logger.error(f"Error in threat classification: {str(e)}")
            raise HTTPException(status_code=500, detail="Error in threat classification")
        
        # Extract IOCs from the text
        try:
            iocs = extract_iocs(request.text)
            logger.info(f"Extracted {len(iocs)} IOCs")
        except Exception as e:
            logger.error(f"Error extracting IOCs: {str(e)}")
            iocs = []
        
        # Enrich IOCs with VirusTotal data if API key is available
        try:
            if os.getenv("VIRUSTOTAL_API_KEY"):
                enriched_iocs = await virustotal_collector.enrich_iocs(iocs)
            else:
                enriched_iocs = iocs
        except Exception as e:
            logger.error(f"Error enriching IOCs: {str(e)}")
            enriched_iocs = iocs
        
        # Get relevant MITRE ATT&CK techniques
        try:
            mitre_techniques = get_mitre_techniques(category)
        except Exception as e:
            logger.error(f"Error getting MITRE techniques: {str(e)}")
            mitre_techniques = []
        
        # Create response
        response = {
            "category": category,
            "confidence": float(confidence),
            "timestamp": datetime.utcnow().isoformat(),
            "iocs": enriched_iocs,
            "mitre_techniques": mitre_techniques
        }
        
        try:
            # Store the analysis result
            threat_intel = ThreatIntelligence(
                threat_type=category,
                source="User Input",
                description=request.text,
                confidence_score=float(confidence),
                indicators={"extracted_iocs": enriched_iocs},
                mitre_techniques=mitre_techniques,
                risk_score=float(confidence * 0.8)
            )
            db.add(threat_intel)
            
            # Store extracted IOCs
            for ioc_data in enriched_iocs:
                ioc = IOC(
                    type=ioc_data["type"],
                    value=ioc_data["value"],
                    confidence_score=float(ioc_data["confidence_score"]),
                    is_active=ioc_data["is_active"],
                    ioc_metadata=ioc_data.get("virustotal", {}),
                    threat_intelligence=threat_intel
                )
                db.add(ioc)
            
            db.commit()
            logger.info(f"Successfully stored threat analysis")
        except Exception as db_error:
            logger.error(f"Database error: {str(db_error)}")
            db.rollback()
            # Continue with response even if database storage fails
        
        return response
        
    except HTTPException as http_exc:
        logger.error(f"HTTP error in threat analysis: {str(http_exc)}")
        raise http_exc
    except Exception as e:
        logger.error(f"Unexpected error in threat analysis: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to analyze threat: {str(e)}"
        )

@router.get("/collect")
async def collect_threats(db: Session = Depends(get_db)):
    """Collect new threats from configured sources"""
    try:
        # Collect from AlienVault
        raw_data = await alienvault_collector.process()
        
        # Transform to STIX format
        stix_data = await alienvault_collector.transform_to_stix(raw_data)
        
        # Store in database
        new_threats = []
        for threat_data in raw_data:
            # Analyze threat description
            category, confidence = classifier.predict(threat_data.get("description", ""))
            
            # Create threat intelligence entry
            threat = ThreatIntelligence(
                threat_type=category,
                source="AlienVault",
                description=threat_data.get("description", ""),
                indicators=threat_data.get("indicators", []),
                risk_score=float(threat_data.get("risk_score", 0.0)),
                confidence_score=confidence,
                mitre_techniques=threat_data.get("mitre_techniques", []),
                geographic_location=threat_data.get("geographic_location", {}),
                raw_data=threat_data
            )
            db.add(threat)
            new_threats.append(threat)
        
        db.commit()
        
        return {
            "status": "success",
            "collected": len(new_threats),
            "timestamp": datetime.utcnow()
        }
        
    except Exception as e:
        logger.error(f"Error collecting threats: {str(e)}")
        raise HTTPException(status_code=500, detail="Error collecting threats")

@router.get("/stats")
async def get_stats(db: Session = Depends(get_db)):
    """Get threat intelligence statistics"""
    try:
        # Use count() directly on the query objects
        total_threats = db.query(ThreatIntelligence).count()
        total_actors = db.query(ThreatActor).count()
        total_iocs = db.query(IOC).count()
        
        # Get threats by type using label()
        threats_by_type = (
            db.query(
                ThreatIntelligence.threat_type,
                func.count(ThreatIntelligence.id).label('count')
            )
            .group_by(ThreatIntelligence.threat_type)
            .all()
        )
        
        # Convert to dictionary
        threats_by_type_dict = {t_type: count for t_type, count in threats_by_type}
        
        # Get recent threats
        recent_date = datetime.utcnow() - timedelta(days=7)
        recent_threats = (
            db.query(ThreatIntelligence)
            .filter(ThreatIntelligence.created_at >= recent_date)
            .count()
        )
        
        return {
            "total_threats": total_threats,
            "total_actors": total_actors,
            "total_iocs": total_iocs,
            "threats_by_type": threats_by_type_dict,
            "recent_threats": recent_threats,
            "timestamp": datetime.utcnow()
        }
        
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Error getting statistics")

@router.post("/analyze-document")
async def analyze_document(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Analyze threats from uploaded PDF document"""
    try:
        if not file.filename.endswith('.pdf'):
            raise HTTPException(status_code=400, detail="Only PDF files are supported")

        # Read PDF content
        content = await file.read()
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(content))
        
        # Extract text from all pages
        extracted_text = ""
        for page in pdf_reader.pages:
            extracted_text += page.extract_text() + "\n"

        # Split text into manageable chunks (e.g., paragraphs)
        text_chunks = [chunk.strip() for chunk in extracted_text.split('\n\n') if chunk.strip()]

        # Analyze each chunk for threats
        analysis_results = []
        for chunk in text_chunks:
            if len(chunk) < 10:  # Skip very short chunks
                continue
                
            # Analyze the chunk using existing threat analysis
            try:
                category, confidence = classifier.predict(chunk)
                iocs = extract_iocs(chunk)
                
                if iocs or confidence > 0.5:  # Only include relevant chunks
                    result = {
                        "text": chunk,
                        "category": category,
                        "confidence": float(confidence),
                        "iocs": iocs
                    }
                    analysis_results.append(result)
                    
                    # Store significant findings
                    if confidence > 0.7:
                        threat_intel = ThreatIntelligence(
                            threat_type=category,
                            source=f"PDF Analysis: {file.filename}",
                            description=chunk,
                            confidence_score=float(confidence),
                            indicators={"extracted_iocs": iocs},
                            risk_score=float(confidence * 0.8)
                        )
                        db.add(threat_intel)
                
            except Exception as e:
                logger.warning(f"Error analyzing chunk: {str(e)}")
                continue

        # Commit all findings to database
        try:
            db.commit()
        except Exception as e:
            logger.error(f"Database error: {str(e)}")
            db.rollback()

        return {
            "filename": file.filename,
            "total_pages": len(pdf_reader.pages),
            "threats_found": len(analysis_results),
            "analysis_results": analysis_results
        }

    except Exception as e:
        logger.error(f"Error processing PDF: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to analyze document: {str(e)}"
        ) 