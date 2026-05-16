# capapp/storage/file_manager.py
"""
Provides static methods for managing the lifecycle of .pcap files
in a thread-safe manner by moving them between directories.
"""
import shutil
from pathlib import Path
from capapp.utils.logger import logger
from capapp.config.settings import config


class FileManager:
    """Manages .pcap file lifecycle through capture → in_progress → processed/error."""

    @staticmethod
    def move_to_in_progress(pcap_path):
        """Atomically moves a file to the 'in_progress' directory."""
        try:
            destination = config.IN_PROGRESS_DIR / pcap_path.name
            shutil.move(str(pcap_path), str(destination))
            return destination
        except FileNotFoundError:
            logger.warning("File %s was moved or deleted before processing.", pcap_path.name)
            return None
        except Exception as e:
            logger.error("Failed to move %s to in_progress: %s", pcap_path.name, e)
            return None

    @staticmethod
    def move_to_processed(pcap_path):
        """Deletes a file from 'in_progress' after successful processing."""
        try:
            if pcap_path.exists():
                pcap_path.unlink()
                logger.info("Deleted processed file: %s", pcap_path.name)
        except Exception as e:
            logger.error("Failed to delete processed file %s: %s", pcap_path.name, e)

    @staticmethod
    def move_to_error(pcap_path):
        """Moves a file that failed processing to the 'error' directory."""
        try:
            destination = config.ERROR_DIR / pcap_path.name
            shutil.move(str(pcap_path), str(destination))
            logger.warning("Moved failed file to error directory: %s", pcap_path.name)
        except Exception as e:
            logger.error("Failed to move %s to error directory: %s", pcap_path.name, e)
