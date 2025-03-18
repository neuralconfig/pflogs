#!/usr/bin/env python3
"""
Threat Intelligence Update Script

This script updates threat intelligence feeds from various sources.
It can be run manually or scheduled via cron to keep the threat intelligence data up-to-date.
"""

import os
import sys
import argparse
import logging
from datetime import datetime
from typing import Optional

# Add parent directory to path so we can import pflogs modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from pflogs.core.threat_intel import ThreatIntelligence

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)), 
                "..", 
                "logs", 
                "threat_intel_update.log"
            )
        )
    ]
)
logger = logging.getLogger(__name__)


def update_threat_intel(data_dir: Optional[str] = None, add_sources: bool = False) -> bool:
    """
    Update threat intelligence feeds.
    
    Args:
        data_dir: Directory to store threat intelligence data
        add_sources: Whether to add additional threat intelligence sources
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Determine data directory
        if not data_dir:
            # Use default directory in the project
            script_dir = os.path.dirname(os.path.abspath(__file__))
            default_data_dir = os.path.abspath(os.path.join(script_dir, '..', 'data', 'threat'))
            data_dir = default_data_dir
            
        # Ensure directory exists
        os.makedirs(data_dir, exist_ok=True)
        
        # Default sources are defined in ThreatIntelligence class
        sources = {}
        
        # Add additional sources if requested
        if add_sources:
            # Add more specialized sources
            sources.update({
                "firehol_level2": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
                "firehol_webserver": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webserver.netset",
                "firehol_anonymous": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset",
                "blocklist_de": "https://lists.blocklist.de/lists/all.txt",
                "alienvault_reputation": "https://reputation.alienvault.com/reputation.data"
            })
        
        # Initialize threat intelligence handler
        threat_intel = ThreatIntelligence(
            data_dir=data_dir,
            sources=sources if sources else None,
            auto_refresh=False
        )
        
        # Update the threat intelligence data
        logger.info(f"Updating threat intelligence feeds in {data_dir}...")
        start_time = datetime.now()
        
        success = threat_intel.refresh_blacklists()
        
        end_time = datetime.now()
        
        if success:
            # Get information about the updated blacklists
            info = threat_intel.get_blacklist_info()
            logger.info(f"Successfully updated threat intelligence feeds in {end_time - start_time}")
            
            # Log information about each source
            for source, source_info in info.items():
                logger.info(f"  {source}: {source_info['count']} entries, updated {source_info['updated']}")
                
            return True
        else:
            logger.error(f"Failed to update some threat intelligence feeds")
            return False
            
    except Exception as e:
        logger.error(f"Error updating threat intelligence: {e}")
        return False


def main():
    """Run the threat intelligence update CLI."""
    parser = argparse.ArgumentParser(
        description="Update threat intelligence feeds from various sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update threat intelligence feeds with default sources
  %(prog)s
  
  # Update threat intelligence feeds in a custom directory
  %(prog)s -d /path/to/threat/data
  
  # Add additional sources
  %(prog)s --add-sources
"""
    )
    
    parser.add_argument(
        "-d", "--dir",
        help="Directory to store threat intelligence data (default: project_root/data/threat)"
    )
    
    parser.add_argument(
        "--add-sources",
        action="store_true",
        help="Add additional threat intelligence sources"
    )
    
    args = parser.parse_args()
    
    # Create logs directory if it doesn't exist
    os.makedirs(
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 
            "..", 
            "logs"
        ), 
        exist_ok=True
    )
    
    # Update the threat intelligence feeds
    success = update_threat_intel(args.dir, args.add_sources)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())