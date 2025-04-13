from abc import ABC, abstractmethod
from typing import List, Dict, Any
from datetime import datetime
from loguru import logger

class BaseCollector(ABC):
    """Base class for all threat intelligence collectors"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.last_collection_time = None
        
    @abstractmethod
    async def collect(self) -> List[Dict[str, Any]]:
        """
        Collect threat intelligence data from the source
        Returns a list of threat intelligence items
        """
        pass
    
    @abstractmethod
    async def validate_data(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Validate collected data
        Returns validated data
        """
        pass
    
    async def process(self) -> List[Dict[str, Any]]:
        """
        Main processing method that handles collection and validation
        """
        try:
            logger.info(f"Starting collection from {self.name}")
            raw_data = await self.collect()
            validated_data = await self.validate_data(raw_data)
            self.last_collection_time = datetime.utcnow()
            logger.info(f"Successfully collected {len(validated_data)} items from {self.name}")
            return validated_data
        except Exception as e:
            logger.error(f"Error collecting data from {self.name}: {str(e)}")
            raise
    
    @abstractmethod
    async def transform_to_stix(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Transform collected data into STIX format
        Returns STIX objects
        """
        pass
    
    def get_collection_status(self) -> Dict[str, Any]:
        """
        Get the current status of the collector
        """
        return {
            "name": self.name,
            "last_collection_time": self.last_collection_time,
            "is_active": True
        } 