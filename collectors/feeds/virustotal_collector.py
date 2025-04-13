import aiohttp
from typing import Dict, List, Any
import os
from loguru import logger

class VirusTotalCollector:
    """Collector for VirusTotal threat intelligence"""
    
    def __init__(self, config: Dict[str, str]):
        self.api_key = config.get("api_key")
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        
    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check a file hash against VirusTotal database"""
        try:
            async with aiohttp.ClientSession() as session:
                params = {
                    'apikey': self.api_key,
                    'resource': file_hash
                }
                async with session.get(f"{self.base_url}/file/report", params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'positives': data.get('positives', 0),
                            'total': data.get('total', 0),
                            'scan_date': data.get('scan_date'),
                            'permalink': data.get('permalink'),
                            'scans': data.get('scans', {})
                        }
                    else:
                        logger.error(f"Error checking hash {file_hash}: {response.status}")
                        return {}
        except Exception as e:
            logger.error(f"Error in VirusTotal API call: {str(e)}")
            return {}
    
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check a domain against VirusTotal database"""
        try:
            async with aiohttp.ClientSession() as session:
                params = {
                    'apikey': self.api_key,
                    'domain': domain
                }
                async with session.get(f"{self.base_url}/domain/report", params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        logger.error(f"Error checking domain {domain}: {response.status}")
                        return {}
        except Exception as e:
            logger.error(f"Error in VirusTotal API call: {str(e)}")
            return {}
    
    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check an IP address against VirusTotal database"""
        try:
            async with aiohttp.ClientSession() as session:
                params = {
                    'apikey': self.api_key,
                    'ip': ip
                }
                async with session.get(f"{self.base_url}/ip-address/report", params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        logger.error(f"Error checking IP {ip}: {response.status}")
                        return {}
        except Exception as e:
            logger.error(f"Error in VirusTotal API call: {str(e)}")
            return {}
    
    async def enrich_iocs(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich IOCs with VirusTotal data"""
        enriched_iocs = []
        
        for ioc in iocs:
            enriched_ioc = ioc.copy()
            
            if ioc['type'] == 'Hash':
                vt_data = await self.check_file_hash(ioc['value'])
                if vt_data:
                    enriched_ioc['virustotal'] = {
                        'detections': f"{vt_data.get('positives', 0)}/{vt_data.get('total', 0)}",
                        'scan_date': vt_data.get('scan_date'),
                        'permalink': vt_data.get('permalink')
                    }
            
            elif ioc['type'] == 'Domain':
                vt_data = await self.check_domain(ioc['value'])
                if vt_data:
                    enriched_ioc['virustotal'] = {
                        'categories': vt_data.get('categories', []),
                        'detected_urls': len(vt_data.get('detected_urls', [])),
                        'detected_communicating_samples': len(vt_data.get('detected_communicating_samples', []))
                    }
            
            elif ioc['type'] == 'IP':
                vt_data = await self.check_ip(ioc['value'])
                if vt_data:
                    enriched_ioc['virustotal'] = {
                        'country': vt_data.get('country', ''),
                        'as_owner': vt_data.get('as_owner', ''),
                        'detected_urls': len(vt_data.get('detected_urls', [])),
                        'detected_samples': len(vt_data.get('detected_samples', []))
                    }
            
            enriched_iocs.append(enriched_ioc)
        
        return enriched_iocs 