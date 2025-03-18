#!/usr/bin/env python3
"""
Setup Cron Job Script

This script sets up a cron job to automatically update threat intelligence feeds daily.
"""

import os
import sys
import argparse
import logging
import subprocess
from typing import Optional

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_cron_job(project_dir: Optional[str] = None, 
                  time: str = "0 3 * * *",
                  add_sources: bool = False) -> bool:
    """
    Set up a cron job to update threat intelligence feeds daily.
    
    Args:
        project_dir: Path to the project directory (default: current script's parent directory)
        time: Cron schedule expression (default: "0 3 * * *", which is 3:00 AM daily)
        add_sources: Whether to include additional threat intelligence sources
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Determine project directory
        if not project_dir:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_dir = os.path.abspath(os.path.join(script_dir, '..'))
            
        # Create the cron job command
        update_script = os.path.join(project_dir, "scripts", "update_threat_intel.py")
        
        # Make sure the update script is executable
        os.chmod(update_script, 0o755)
        
        # Construct the cron job command
        cmd = f"{time} {update_script}"
        if add_sources:
            cmd += " --add-sources"
            
        # Add the cron job
        import tempfile
        cron_file = tempfile.mktemp()
        try:
            # Get existing crontab
            subprocess.run("crontab -l > " + cron_file, shell=True, check=False)
        except:
            # If crontab doesn't exist, create an empty file
            with open(cron_file, 'w') as f:
                f.write("")
                
        # Add the new cron job if it doesn't already exist
        with open(cron_file, 'r') as f:
            cron_content = f.read()
            
        if update_script not in cron_content:
            # Add comment above cron job
            with open(cron_file, 'a') as f:
                f.write(f"\n# Daily update of threat intelligence feeds for pflogs\n")
                f.write(f"{cmd}\n")
                
            # Install the new crontab
            subprocess.run("crontab " + cron_file, shell=True, check=True)
            logger.info(f"Cron job installed: {cmd}")
        else:
            logger.info(f"Cron job already exists for {update_script}")
            
        # Clean up the temporary file
        os.unlink(cron_file)
        
        return True
        
    except Exception as e:
        logger.error(f"Error setting up cron job: {e}")
        return False


def main():
    """Run the cron job setup CLI."""
    parser = argparse.ArgumentParser(
        description="Set up a cron job to automatically update threat intelligence feeds daily",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Set up a daily cron job at 3:00 AM
  %(prog)s
  
  # Set up a daily cron job at a custom time (1:30 AM)
  %(prog)s --time "30 1 * * *"
  
  # Add additional threat intelligence sources
  %(prog)s --add-sources
"""
    )
    
    parser.add_argument(
        "-d", "--dir",
        help="Path to the project directory (default: current script's parent directory)"
    )
    
    parser.add_argument(
        "-t", "--time",
        default="0 3 * * *",
        help="Cron schedule expression (default: \"0 3 * * *\", which is 3:00 AM daily)"
    )
    
    parser.add_argument(
        "--add-sources",
        action="store_true",
        help="Include additional threat intelligence sources"
    )
    
    args = parser.parse_args()
    
    # Set up the cron job
    success = setup_cron_job(args.dir, args.time, args.add_sources)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())