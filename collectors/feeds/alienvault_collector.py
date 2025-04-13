import aiohttp
from typing import List, Dict, Any
from datetime import datetime, timedelta
from .base_collector import BaseCollector
from loguru import logger
import json
from stix2 import Indicator, ThreatActor, Relationship

class AlienVaultCollector(BaseCollector):
    """Collector for AlienVault OTX threat intelligence feed"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("AlienVault OTX", config)
        self.api_key = config.get("api_key")
        self.base_url = "https://otx.alienvault.com/api/v1"
        if not self.api_key:
            raise ValueError("AlienVault API key is required")
    
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect threat data from AlienVault OTX"""
        async with aiohttp.ClientSession() as session:
            # Get pulses from the last 24 hours
            since = datetime.utcnow() - timedelta(days=1)
            headers = {"X-OTX-API-KEY": self.api_key}
            
            try:
                async with session.get(
                    f"{self.base_url}/pulses/subscribed",
                    headers=headers,
                    params={"modified_since": since.isoformat()}
                ) as response:
                    response.raise_for_status()
                    data = await response.json()
                    return data.get("results", [])
            except Exception as e:
                logger.error(f"Error collecting from AlienVault: {str(e)}")
                raise
    
    async def validate_data(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate collected data from AlienVault"""
        validated_data = []
        
        for pulse in data:
            if not all(k in pulse for k in ["name", "description", "indicators"]):
                logger.warning(f"Skipping invalid pulse: {pulse.get('name', 'Unknown')}")
                continue
                
            # Validate indicators
            valid_indicators = []
            for indicator in pulse["indicators"]:
                if all(k in indicator for k in ["type", "indicator"]):
                    valid_indicators.append(indicator)
                
            if valid_indicators:
                pulse["indicators"] = valid_indicators
                validated_data.append(pulse)
        
        return validated_data
    
    async def transform_to_stix(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Transform AlienVault data to STIX format"""
        stix_objects = []
        
        for pulse in data:
            # Create ThreatActor object
            actor = ThreatActor(
                name=pulse["author_name"],
                description=pulse.get("description", ""),
                aliases=pulse.get("tags", [])
            )
            stix_objects.append(actor)
            
            # Create Indicator objects
            for ioc in pulse["indicators"]:
                indicator = Indicator(
                    name=f"{ioc['type']} - {ioc['indicator']}",
                    pattern=f"[{ioc['type']}:value = '{ioc['indicator']}']",
                    pattern_type="stix",
                    valid_from=datetime.utcnow()
                )
                stix_objects.append(indicator)
                
                # Create relationship between indicator and threat actor
                relationship = Relationship(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=actor.id
                )
                stix_objects.append(relationship)
        
        return [obj.serialize() for obj in stix_objects]
    
    async def get_pulse_details(self, pulse_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific pulse"""
        async with aiohttp.ClientSession() as session:
            headers = {"X-OTX-API-KEY": self.api_key}
            
            try:
                async with session.get(
                    f"{self.base_url}/pulses/{pulse_id}",
                    headers=headers
                ) as response:
                    response.raise_for_status()
                    return await response.json()
            except Exception as e:
                logger.error(f"Error getting pulse details: {str(e)}")
                raise 