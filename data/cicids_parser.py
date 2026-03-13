"""
CICIDS2017 Dataset Parser for SENTINEL-AI

Converts CICIDS2017 CSV data into normalized JSON alert format.
Extracts 200 alerts (100 benign + 100 attack) for demonstration purposes.
"""

import pandas as pd
import json
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import random

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CICIDSParser:
    """Parser for CICIDS2017 intrusion detection dataset."""
    
    def __init__(self, dataset_path: str, output_path: str):
        """
        Initialize the parser.
        
        Args:
            dataset_path: Path to CICIDS2017 CSV files
            output_path: Path to save processed JSON alerts
        """
        self.dataset_path = Path(dataset_path)
        self.output_path = Path(output_path)
        self.output_path.mkdir(parents=True, exist_ok=True)
        
        # CICIDS2017 attack type mappings
        self.attack_severity_map = {
            'BENIGN': 'P4',  # Low priority - normal traffic
            'DoS Hulk': 'P1',  # Critical - Denial of Service
            'DoS GoldenEye': 'P1',  # Critical - Denial of Service
            'DoS slowloris': 'P1',  # Critical - Denial of Service
            'DoS Slowhttptest': 'P1',  # Critical - Denial of Service
            'DDoS': 'P1',  # Critical - Distributed Denial of Service
            'PortScan': 'P2',  # High - Reconnaissance activity
            'Brute Force -Web': 'P2',  # High - Credential attack
            'Brute Force -XSS': 'P2',  # High - Web application attack
            'SQL Injection': 'P1',  # Critical - Data breach risk
            'Infiltration': 'P1',  # Critical - System compromise
            'Bot': 'P2',  # High - Malware activity
            'Web Attack - Brute Force': 'P2',  # High
            'Web Attack - XSS': 'P2',  # High
            'Web Attack - Sql Injection': 'P1',  # Critical
            'Heartbleed': 'P1'  # Critical - SSL vulnerability
        }
        
        # MITRE ATT&CK technique mappings (simplified for demo)
        self.mitre_technique_map = {
            'DoS Hulk': 'T1499.002',  # Network DoS
            'DoS GoldenEye': 'T1499.002',
            'DoS slowloris': 'T1499.002',
            'DoS Slowhttptest': 'T1499.002',
            'DDoS': 'T1499.002',
            'PortScan': 'T1046',  # Network Service Scanning
            'Brute Force -Web': 'T1110.001',  # Password Brute Force
            'Brute Force -XSS': 'T1110.001',
            'SQL Injection': 'T1190',  # Exploit Public-Facing Application
            'Infiltration': 'T1055',  # Process Injection
            'Bot': 'T1059',  # Command and Scripting Interpreter
            'Web Attack - Brute Force': 'T1110.001',
            'Web Attack - XSS': 'T1059.007',  # JavaScript/JScript
            'Web Attack - Sql Injection': 'T1190',
            'Heartbleed': 'T1190',
            'BENIGN': 'T0000'  # No technique for benign traffic
        }

    def generate_alert_id(self, row: Dict) -> str:
        """Generate unique alert ID from row data."""
        content = f"{row.get('Source IP', '')}{row.get('Destination IP', '')}{row.get('Timestamp', '')}"
        return hashlib.md5(content.encode()).hexdigest()[:12]

    def extract_features_from_row(self, row: Dict) -> Dict[str, Any]:
        """Extract relevant features from CICIDS2017 row."""
        # Get the label (attack type or BENIGN)
        label = str(row.get('Label', 'Unknown')).strip()
        
        # Create raw payload simulation (what would appear in logs)
        source_ip = str(row.get('Source IP', '0.0.0.0'))
        dest_ip = str(row.get('Destination IP', '0.0.0.0'))
        dest_port = str(row.get('Destination Port', '0'))
        protocol = str(row.get('Protocol', '0'))
        
        # Protocol mapping
        protocol_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}
        protocol_name = protocol_map.get(protocol, f'Protocol-{protocol}')
        
        # Create realistic log entry
        if label == 'BENIGN':
            raw_payload = f"[{datetime.now().isoformat()}] ALLOW {protocol_name} {source_ip}:{row.get('Source Port', 0)} -> {dest_ip}:{dest_port} (Normal traffic)"
        else:
            raw_payload = f"[{datetime.now().isoformat()}] ALERT {protocol_name} {source_ip}:{row.get('Source Port', 0)} -> {dest_ip}:{dest_port} Suspicious activity detected: {label}"
        
        return {
            'alert_id': self.generate_alert_id(row),
            'raw_payload': raw_payload,
            'source_ip': source_ip,
            'destination_ip': dest_ip,
            'destination_port': int(float(str(dest_port)) if dest_port.replace('.', '').isdigit() else 0),
            'protocol': protocol_name,
            'event_type': label,
            'true_severity': self.attack_severity_map.get(label, 'P3'),
            'true_mitre_technique': self.mitre_technique_map.get(label, 'T0000'),
            'flow_duration': float(row.get('Flow Duration', 0)),
            'total_fwd_packets': int(float(str(row.get('Total Fwd Packets', 0))) if str(row.get('Total Fwd Packets', 0)).replace('.', '').replace('-', '').isdigit() else 0),
            'total_backward_packets': int(float(str(row.get('Total Backward Packets', 0))) if str(row.get('Total Backward Packets', 0)).replace('.', '').replace('-', '').isdigit() else 0),
            'flow_bytes_per_sec': float(row.get('Flow Bytes/s', 0)) if str(row.get('Flow Bytes/s', 0)).replace('.', '').replace('-', '').replace('e', '').replace('+', '').isdigit() else 0,
            'timestamp': datetime.now().isoformat()
        }

    def load_cicids_data(self) -> pd.DataFrame:
        """Load CICIDS2017 CSV files and combine them."""
        all_data = []
        csv_files = list(self.dataset_path.glob("*.csv"))
        
        if not csv_files:
            # Create synthetic data if no CSV files found
            logger.warning("No CICIDS2017 CSV files found. Creating synthetic data for demonstration.")
            return self.create_synthetic_data()
        
        for csv_file in csv_files:
            try:
                logger.info(f"Loading {csv_file.name}")
                df = pd.read_csv(csv_file)
                all_data.append(df)
            except Exception as e:
                logger.error(f"Error loading {csv_file}: {e}")
                continue
        
        if not all_data:
            logger.warning("No valid CSV data loaded. Creating synthetic data.")
            return self.create_synthetic_data()
        
        combined_df = pd.concat(all_data, ignore_index=True)
        logger.info(f"Loaded {len(combined_df)} total records")
        
        return combined_df

    def create_synthetic_data(self) -> pd.DataFrame:
        """Create synthetic CICIDS2017-like data for demonstration."""
        logger.info("Creating synthetic CICIDS2017-like data")
        
        synthetic_data = []
        
        # Create 100 benign records
        for i in range(100):
            synthetic_data.append({
                'Source IP': f"192.168.1.{random.randint(1, 254)}",
                'Destination IP': f"10.0.0.{random.randint(1, 254)}",
                'Source Port': random.randint(1024, 65535),
                'Destination Port': random.choice([80, 443, 22, 53, 21]),
                'Protocol': '6',  # TCP
                'Flow Duration': random.randint(100, 10000),
                'Total Fwd Packets': random.randint(1, 100),
                'Total Backward Packets': random.randint(1, 100),
                'Flow Bytes/s': random.randint(1000, 100000),
                'Label': 'BENIGN'
            })
        
        # Create 100 attack records (20 of each type)
        attack_types = ['DoS Hulk', 'PortScan', 'Brute Force -Web', 'SQL Injection', 'Bot']
        for attack_type in attack_types:
            for i in range(20):
                synthetic_data.append({
                    'Source IP': f"192.168.100.{random.randint(1, 100)}",
                    'Destination IP': f"172.16.0.{random.randint(1, 254)}",
                    'Source Port': random.randint(1024, 65535),
                    'Destination Port': random.choice([80, 443, 22, 3389]),
                    'Protocol': '6',
                    'Flow Duration': random.randint(50, 5000),
                    'Total Fwd Packets': random.randint(10, 1000),
                    'Total Backward Packets': random.randint(0, 50),
                    'Flow Bytes/s': random.randint(10000, 1000000),
                    'Label': attack_type
                })
        
        return pd.DataFrame(synthetic_data)

    def sample_alerts(self, df: pd.DataFrame, total_samples: int = 200) -> pd.DataFrame:
        """Sample balanced dataset: 100 benign + 100 attack alerts."""
        benign_data = df[df['Label'] == 'BENIGN']
        attack_data = df[df['Label'] != 'BENIGN']
        
        # Sample 100 benign alerts
        if len(benign_data) >= 100:
            benign_sample = benign_data.sample(n=100, random_state=42)
        else:
            benign_sample = benign_data
            logger.warning(f"Only {len(benign_data)} benign samples available")
        
        # Sample 100 attack alerts (distributed across attack types)
        attack_sample_size = total_samples - len(benign_sample)
        if len(attack_data) >= attack_sample_size:
            attack_sample = attack_data.sample(n=attack_sample_size, random_state=42)
        else:
            attack_sample = attack_data
            logger.warning(f"Only {len(attack_data)} attack samples available")
        
        # Combine and shuffle
        sample_df = pd.concat([benign_sample, attack_sample], ignore_index=True)
        sample_df = sample_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        logger.info(f"Sampled {len(sample_df)} alerts ({len(benign_sample)} benign, {len(attack_sample)} attacks)")
        return sample_df

    def process_to_json(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Convert DataFrame to list of JSON alert objects."""
        alerts = []
        
        for idx, row in df.iterrows():
            try:
                alert = self.extract_features_from_row(row.to_dict())
                alerts.append(alert)
            except Exception as e:
                logger.error(f"Error processing row {idx}: {e}")
                continue
        
        logger.info(f"Processed {len(alerts)} alerts successfully")
        return alerts

    def save_alerts(self, alerts: List[Dict[str, Any]], filename: str = "cicids_alerts.json"):
        """Save processed alerts to JSON file."""
        output_file = self.output_path / filename
        
        with open(output_file, 'w') as f:
            json.dump(alerts, f, indent=2, default=str)
        
        logger.info(f"Saved {len(alerts)} alerts to {output_file}")
        return output_file

    def run(self) -> str:
        """Run the complete parsing pipeline."""
        logger.info("Starting CICIDS2017 data processing pipeline")
        
        # Load raw data
        df = self.load_cicids_data()
        
        # Sample 200 alerts
        sample_df = self.sample_alerts(df)
        
        # Convert to JSON format
        alerts = self.process_to_json(sample_df)
        
        # Save processed alerts
        output_file = self.save_alerts(alerts)
        
        # Generate summary statistics
        self.generate_summary(alerts, output_file.parent / "processing_summary.txt")
        
        logger.info("CICIDS2017 processing pipeline completed successfully")
        return str(output_file)

    def generate_summary(self, alerts: List[Dict[str, Any]], summary_file: Path):
        """Generate processing summary statistics."""
        # Count by event type
        event_counts = {}
        severity_counts = {}
        
        for alert in alerts:
            event_type = alert['event_type']
            severity = alert['true_severity']
            
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Write summary
        with open(summary_file, 'w') as f:
            f.write("CICIDS2017 Processing Summary\n")
            f.write("="*40 + "\n\n")
            f.write(f"Total alerts processed: {len(alerts)}\n\n")
            
            f.write("Event Types:\n")
            for event_type, count in sorted(event_counts.items()):
                f.write(f"  {event_type}: {count}\n")
            
            f.write("\nSeverity Distribution:\n")
            for severity, count in sorted(severity_counts.items()):
                f.write(f"  {severity}: {count}\n")
        
        logger.info(f"Summary saved to {summary_file}")


# Test function for standalone execution
def main():
    """Test function to run the parser."""
    import os
    from dotenv import load_dotenv
    
    # Load environment variables
    load_dotenv()
    
    # Default paths
    dataset_path = os.getenv('CICIDS_PATH', './data/raw/')
    output_path = os.getenv('PROCESSED_DATA_PATH', './data/processed/')
    
    # Run parser
    parser = CICIDSParser(dataset_path, output_path)
    output_file = parser.run()
    
    print(f"Processing complete! Output saved to: {output_file}")


if __name__ == "__main__":
    main()