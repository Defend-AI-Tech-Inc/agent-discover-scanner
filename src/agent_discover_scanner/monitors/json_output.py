"""JSON output formatter for detections."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, TextIO


class JSONLogger:
    """Log detections to JSON/JSONL format."""
    
    def __init__(self, output_file: Optional[Path] = None, format: str = "jsonl"):
        """
        Initialize JSON logger.
        
        Args:
            output_file: Path to output file (None = stdout)
            format: "json" for array, "jsonl" for line-delimited
        """
        self.output_file = output_file
        self.format = format
        self.detections = []
        self.file_handle: Optional[TextIO] = None
        
        if output_file and format == "jsonl":
            self.file_handle = open(output_file, "a")
    
    def log_detection(self, detection: dict):
        """Log a single detection."""
        # Add to memory
        self.detections.append(detection)
        
        # Write to file if JSONL
        if self.file_handle and self.format == "jsonl":
            # Convert datetime to ISO string
            detection_copy = detection.copy()
            if isinstance(detection_copy.get("timestamp"), datetime):
                detection_copy["timestamp"] = detection_copy["timestamp"].isoformat()
            
            self.file_handle.write(json.dumps(detection_copy) + "\n")
            self.file_handle.flush()
    
    def save_json(self):
        """Save all detections as JSON array (for format="json")."""
        if self.output_file and self.format == "json":
            # Convert datetimes
            detections_serializable = []
            for d in self.detections:
                d_copy = d.copy()
                if isinstance(d_copy.get("timestamp"), datetime):
                    d_copy["timestamp"] = d_copy["timestamp"].isoformat()
                detections_serializable.append(d_copy)
            
            with open(self.output_file, "w") as f:
                json.dump(detections_serializable, f, indent=2)
    
    def close(self):
        """Close file handle."""
        if self.file_handle:
            self.file_handle.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        if self.format == "json":
            self.save_json()
