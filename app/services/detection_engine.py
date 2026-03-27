import asyncio
import numpy as np
import joblib
import tensorflow as tf
from typing import Dict, List, Optional, Any
from datetime import datetime
from time import perf_counter
import structlog
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from pathlib import Path
import glob

from app.models.schemas import AttackType, HoneypotLog, DetectionResult, ThreatLevel
from app.config import settings

logger = structlog.get_logger()


class DetectionEngine:
    """
    Hybrid Detection Engine combining:
    1. Signature-based detection (known threats)
    2. Anomaly detection (ML-based, unknown threats)
    3. Reinforcement Learning for adaptive thresholds
    """
    
    def __init__(self):
        self.signature_rules = []
        self.anomaly_model = None
        self.classifier_model = None
        self.scaler = StandardScaler()
        self.feature_cache = {}
        self.initialized = False
        
    async def load_models(self):
        """Load trained ML models from Dionaea training"""
        logger.info("Loading trained Dionaea models...")
        
        model_dir = settings.MODEL_STORAGE_PATH
        
        try:
            # Load preprocessor first
            preprocessor_path = f"{model_dir}/preprocessor.pkl"
            if Path(preprocessor_path).exists():
                from app.ml.preprocessor import DionaeaPreprocessor
                self.preprocessor = DionaeaPreprocessor()
                self.preprocessor.load(preprocessor_path)
                logger.info("Dionaea preprocessor loaded", 
                        features=len(self.preprocessor.feature_names))
            
            # Load binary classifier (attack vs normal)
            binary_models = glob.glob(f"{model_dir}/airs_binary_*.pkl")
            if binary_models:
                latest = max(binary_models, key=lambda x: Path(x).stat().st_mtime)
                self.classifier_model = joblib.load(latest)
                logger.info("Binary classifier loaded", path=latest)
            
            # Load anomaly detector
            anomaly_models = glob.glob(f"{model_dir}/airs_anomaly_*.pkl")
            if anomaly_models:
                latest = max(anomaly_models, key=lambda x: Path(x).stat().st_mtime)
                self.anomaly_model = joblib.load(latest)
                logger.info("Anomaly detector loaded", path=latest)
            
            # Load category classifier
            category_models = glob.glob(f"{model_dir}/airs_category_*.pkl")
            if category_models:
                latest = max(category_models, key=lambda x: Path(x).stat().st_mtime)
                self.category_model = joblib.load(latest)
                logger.info("Category classifier loaded", path=latest)
            
            # Load signature rules as fallback
            await self._load_signatures()
            
            self.initialized = True
            logger.info("All Dionaea models loaded successfully")
            
        except Exception as e:
            logger.error("Failed to load trained models, using fallback", error=str(e))
            # Fallback to basic models
            await self._load_fallback_models()
            
    async def _load_signatures(self):
        """Load YARA-style or custom signatures"""
        # Placeholder: Load from database or file
        self.signature_rules = [
            {
                "id": "SIG-001",
                "name": "SSH Brute Force",
                "pattern": r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
                "attack_type": "brute_force",
                "threat_level": "high"
            },
            {
                "id": "SIG-002", 
                "name": "Common Malware Download",
                "pattern": r"(wget|curl).*\.(sh|bin|elf)",
                "attack_type": "malware",
                "threat_level": "critical"
            }
        ]
        
    async def analyze(self, log: HoneypotLog) -> DetectionResult:
        """
        Main analysis pipeline:
        1. Fast packet/header prescan to select detector
        2. Execute the selected detector path
        3. Fall back if the selected path does not produce a threat
        4. Return a normalized detection result
        """
        if not self.initialized:
            await self.load_models()

        prescan = self._fast_header_scan(log)
        logger.info(
            "Detection prescan completed",
            source_ip=log.source_ip,
            session_id=log.session_id,
            preferred_method=prescan["preferred_method"],
            duration_us=prescan["duration_us"],
            indicators=prescan["indicators"],
        )

        features = self._extract_dionaea_features(log)
        features["prescan_duration_us"] = prescan["duration_us"]
        features["prescan_indicator_count"] = len(prescan["indicators"])
        features["preferred_detection_method"] = prescan["preferred_method"]

        if prescan["preferred_method"] == "signature":
            sig_match = self._check_signatures(log, features)
            if sig_match:
                logger.warning(
                    "Signature detection matched",
                    source_ip=log.source_ip,
                    session_id=log.session_id,
                    signature_id=sig_match["id"],
                    attack_type=sig_match["attack_type"],
                )
                return self._create_signature_result(sig_match, features)

            logger.info(
                "Signature route produced no match, falling back to anomaly detection",
                source_ip=log.source_ip,
                session_id=log.session_id,
            )

        return self._run_anomaly_detection(log, features)

    def _run_anomaly_detection(self, log: HoneypotLog, features: Dict[str, Any]) -> DetectionResult:
        """Run trained ML/anomaly pipeline after routing."""
        if hasattr(self, 'preprocessor') and self.preprocessor and self.preprocessor.is_fitted:
            try:
                feature_vector = self._vectorize_for_preprocessor(features)
                X_scaled = self.preprocessor.scaler.transform([feature_vector])
            except Exception as e:
                logger.warning("Preprocessor failed, using raw features", error=str(e))
                X_scaled = [list(features.values())]
        else:
            X_scaled = [list(features.values())]
        
        is_attack = False
        attack_confidence = 0.0
        
        if hasattr(self, 'classifier_model') and self.classifier_model:
            try:
                prediction = self.classifier_model.predict(X_scaled)[0]
                proba = self.classifier_model.predict_proba(X_scaled)[0]
                is_attack = prediction == 1
                attack_confidence = proba[1] if len(proba) > 1 else 0.5
            except Exception as e:
                logger.warning("Binary classifier failed", error=str(e))
        
        anomaly_score = 0.0
        if hasattr(self, 'anomaly_model') and self.anomaly_model:
            try:
                raw_score = self.anomaly_model.score_samples(X_scaled)[0]
                anomaly_score = 1.0 / (1.0 + np.exp(-raw_score))
                is_anomaly = self.anomaly_model.predict(X_scaled)[0] == -1
                if is_anomaly:
                    is_attack = True
                    attack_confidence = max(attack_confidence, 0.7)
            except Exception as e:
                logger.warning("Anomaly detector failed", error=str(e))
        
        attack_type = AttackType.UNKNOWN
        if is_attack and hasattr(self, 'category_model') and self.category_model:
            try:
                cat_prediction = self.category_model.predict(X_scaled)[0]
                attack_type = self._map_category_to_attack_type(cat_prediction)
            except Exception as e:
                logger.warning("Category classifier failed", error=str(e))
                attack_type = self._infer_attack_type_from_features(features)
        
        if is_attack:
            threat_level = self._calculate_threat_level(attack_confidence, anomaly_score, attack_type)
            logger.warning(
                "Anomaly detection flagged threat",
                source_ip=log.source_ip,
                session_id=log.session_id,
                attack_type=attack_type.value,
                confidence=attack_confidence,
                anomaly_score=anomaly_score,
                threat_level=threat_level.value if hasattr(threat_level, "value") else threat_level,
            )

            return DetectionResult(
                threat_detected=True,
                threat_level=threat_level,
                attack_type=attack_type,
                confidence_score=attack_confidence,
                detection_method="anomaly",
                anomaly_score=anomaly_score,
                features=features,
                mitre_mapping=self._map_to_mitre(attack_type.value),
                recommendation=f"Trained model detected {attack_type.value} with {attack_confidence:.1%} confidence"
            )
        
        return DetectionResult(
            threat_detected=False,
            threat_level=ThreatLevel.LOW,
            confidence_score=1.0 - attack_confidence,
            detection_method="anomaly",
            features=features
        )

    def _fast_header_scan(self, log: HoneypotLog) -> Dict[str, Any]:
        """
        Perform a very small prescan on packet/session header fields to pick
        the most appropriate detection method before deeper inspection.
        """
        started = perf_counter()
        indicators = []
        preferred_method = "anomaly"

        meta = getattr(log, "meta_data", {}) or {}
        protocol = (log.protocol or "").lower()
        event_type = (log.event_type or "").lower()
        command = (log.command or "").lower()
        payload = (log.payload or "").lower()

        if log.dest_port in {21, 22, 23, 445, 3389}:
            indicators.append(f"monitored_port:{log.dest_port}")
        if event_type in {"login_attempt", "command_execution", "file_upload"}:
            indicators.append(f"event:{event_type}")
        if any(token in command for token in ("wget", "curl", "chmod", "powershell")):
            indicators.append("command_ioc")
        if any(token in payload for token in ("failed password", "/bin/sh", "cmd.exe")):
            indicators.append("payload_ioc")
        if meta.get("dionaea_download_url") or meta.get("dionaea_file_type"):
            indicators.append("download_observed")
        if protocol in {"tcp", "udp"}:
            indicators.append(f"transport:{protocol}")

        if {"command_ioc", "payload_ioc", "download_observed"} & set(indicators):
            preferred_method = "signature"
        elif len(indicators) >= 3 and log.dest_port not in {80, 443}:
            preferred_method = "signature"

        duration_us = max(int((perf_counter() - started) * 1_000_000), 1)
        return {
            "preferred_method": preferred_method,
            "duration_us": duration_us,
            "indicators": indicators,
        }
    
    def _extract_features(self, log: HoneypotLog) -> Dict[str, Any]:
        """Extract numerical and categorical features from log"""
        features = {
            "timestamp_hour": log.timestamp.hour,
            "source_ip_octets": [int(x) for x in log.source_ip.split(".")],
            "dest_port": log.dest_port,
            "protocol_hash": hash(log.protocol) % 1000,
            "event_type_hash": hash(log.event_type) % 1000,
            "has_payload": 1 if log.payload else 0,
            "payload_length": len(log.payload) if log.payload else 0,
            "command_complexity": len(log.command.split()) if log.command else 0,
            "username_entropy": self._calculate_entropy(log.username) if log.username else 0,
            "password_entropy": self._calculate_entropy(log.password) if log.password else 0,
        }
        
        # Add behavioral features (rate-based)
        features.update(self._get_behavioral_features(log.source_ip))
        
        return features
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy for string randomness"""
        import math
        from collections import Counter
        if not string:
            return 0
        counts = Counter(string)
        length = len(string)
        return -sum((count/length) * math.log2(count/length) for count in counts.values())
    
    def _get_behavioral_features(self, ip: str) -> Dict[str, float]:
        """Get rate-based features for IP (implement with Redis/cache)"""
        # Placeholder: Implement with actual caching
        return {
            "requests_per_minute": 0.0,
            "unique_ports_accessed": 0,
            "failed_login_ratio": 0.0
        }
    
    def _check_signatures(self, log: HoneypotLog, features: Dict = None) -> Optional[Dict]:
        """Check against known attack signatures"""
        import re
        
        check_string = f"{log.command or ''} {log.payload or ''} {log.username or ''}"
        
        for rule in self.signature_rules:
            if re.search(rule["pattern"], check_string, re.IGNORECASE):
                return rule
        return None
    
    async def _detect_anomaly(self, features: Dict) -> Dict:
        """Detect anomalies using Isolation Forest or Autoencoder"""
        if self.anomaly_model is None:
            return {"is_anomaly": False, "score": 0.0}
        
        # Convert features to vector
        feature_vector = self._vectorize_features(features)
        
        # Predict
        if hasattr(self.anomaly_model, 'predict'):
            prediction = self.anomaly_model.predict([feature_vector])[0]
            score = self.anomaly_model.score_samples([feature_vector])[0]
            return {
                "is_anomaly": prediction == -1,
                "score": abs(score)
            }
        
        return {"is_anomaly": False, "score": 0.0}
    
    async def _classify_threat(self, features: Dict) -> Dict:
        """Classify threat type using neural network"""
        if self.classifier_model is None:
            return {"type": "unknown", "confidence": 0.5}
        
        feature_vector = self._vectorize_features(features)
        prediction = self.classifier_model.predict([feature_vector])[0]
        
        attack_types = ["reconnaissance", "exploitation", "malware", "brute_force", "normal"]
        predicted_class = np.argmax(prediction)
        
        return {
            "type": attack_types[predicted_class],
            "confidence": float(prediction[predicted_class])
        }
    
    def _vectorize_features(self, features: Dict) -> np.ndarray:
        """Convert feature dict to numpy array"""
        # Implement consistent feature ordering
        ordered = [
            features.get("timestamp_hour", 0),
            features.get("dest_port", 0),
            features.get("has_payload", 0),
            features.get("payload_length", 0),
            features.get("command_complexity", 0),
            features.get("username_entropy", 0),
            features.get("password_entropy", 0),
            features.get("requests_per_minute", 0),
            features.get("unique_ports_accessed", 0),
            features.get("failed_login_ratio", 0),
        ]
        return np.array(ordered)
    
    def _create_signature_result(self, match: Dict, features: Dict) -> DetectionResult:
        return DetectionResult(
            threat_detected=True,
            threat_level=match["threat_level"],
            attack_type=match["attack_type"],
            confidence_score=0.95,
            detection_method="signature",
            signature_match=match["id"],
            features=features,
            mitre_mapping=self._map_to_mitre(match["attack_type"])
        )
    
    def _create_ml_result(self, anomaly: Dict, classification: Dict, features: Dict) -> DetectionResult:
        confidence = classification.get("confidence", 0.8) * anomaly["score"]
        
        return DetectionResult(
            threat_detected=True,
            threat_level="high" if confidence > 0.9 else "medium",
            attack_type=classification["type"],
            confidence_score=confidence,
            detection_method="anomaly",
            anomaly_score=anomaly["score"],
            features=features,
            mitre_mapping=self._map_to_mitre(classification["type"])
        )
    
    def _map_to_mitre(self, attack_type: str) -> Dict[str, str]:
        """Map attack type to MITRE ATT&CK framework"""
        mapping = {
            "brute_force": {"tactic": "Credential Access", "technique": "T1110"},
            "malware": {"tactic": "Execution", "technique": "T1204"},
            "exploitation": {"tactic": "Initial Access", "technique": "T1190"},
            "reconnaissance": {"tactic": "Reconnaissance", "technique": "T1595"},
        }
        return mapping.get(attack_type, {"tactic": "Unknown", "technique": "T0000"})

    async def cleanup(self):
        """Cleanup resources"""
        logger.info("Detection engine cleanup")

    # Add this method to your DetectionEngine class in detection_engine.py

    async def load_trained_models(self, model_dir: str = "models"):
        """Load models trained on Dionaea dataset"""
        import joblib
        import glob
        from tensorflow import keras
        
        logger.info("Loading trained models from", model_dir=model_dir)
        
        try:
            # Load preprocessor
            preprocessor_path = f"{model_dir}/preprocessor.pkl"
            if Path(preprocessor_path).exists():
                from app.ml.preprocessor import DionaeaPreprocessor
                self.preprocessor = DionaeaPreprocessor()
                self.preprocessor.load(preprocessor_path)
                logger.info("Preprocessor loaded")
            
            # Load binary classifier
            binary_models = glob.glob(f"{model_dir}/airs_binary_*.pkl")
            if binary_models:
                latest = max(binary_models, key=lambda x: Path(x).stat().st_mtime)
                self.classifier_model = joblib.load(latest)
                logger.info("Binary classifier loaded", path=latest)
            
            # Load anomaly detector
            anomaly_models = glob.glob(f"{model_dir}/airs_anomaly_*.pkl")
            if anomaly_models:
                latest = max(anomaly_models, key=lambda x: Path(x).stat().st_mtime)
                self.anomaly_model = joblib.load(latest)
                logger.info("Anomaly detector loaded", path=latest)
            
            # Load category classifier
            category_models = glob.glob(f"{model_dir}/airs_category_*.pkl")
            if category_models:
                latest = max(category_models, key=lambda x: Path(x).stat().st_mtime)
                self.category_model = joblib.load(latest)
                logger.info("Category classifier loaded", path=latest)
            
            self.initialized = True
            
        except Exception as e:
            logger.error("Failed to load trained models", error=str(e))
            # Fall back to default initialization
            await self._load_ml_models()

    def _extract_dionaea_features(self, log: HoneypotLog) -> Dict[str, Any]:
        """Extract features matching Dionaea training data format"""
        
        # Start with basic features
        features = {
            # Temporal
            'hour': log.timestamp.hour if hasattr(log, 'timestamp') else 0,
            'day_of_week': log.timestamp.weekday() if hasattr(log, 'timestamp') else 0,
            'is_weekend': 1 if log.timestamp.weekday() >= 5 else 0,
            'is_night': 1 if (log.timestamp.hour < 6 or log.timestamp.hour > 22) else 0,
            
            # Network
            'remote_port': log.source_port,
            'local_port': log.dest_port,
            'is_common_port': 1 if log.dest_port in [22, 80, 443, 21, 25, 3306, 5432] else 0,
        }
        
        # Parse IP octets
        try:
            octets = log.source_ip.split('.')
            features['remote_ip_octet_1'] = int(octets[0]) if len(octets) > 0 else 0
            features['remote_ip_octet_2'] = int(octets[1]) if len(octets) > 1 else 0
            features['remote_ip_octet_3'] = int(octets[2]) if len(octets) > 2 else 0
            features['remote_ip_octet_4'] = int(octets[3]) if len(octets) > 3 else 0
        except:
            features['remote_ip_octet_1'] = 0
            features['remote_ip_octet_2'] = 0
            features['remote_ip_octet_3'] = 0
            features['remote_ip_octet_4'] = 0
        
        # Protocol indicators from meta_data
        meta = getattr(log, 'meta_data', {}) or {}
        
        protocol_map = {
            'has_http': ['http_method', 'http_url', 'http_user_agent'],
            'has_smb': ['smb_command', 'smb_file'],
            'has_ftp': ['ftp_command', 'ftp_arg'],
            'has_mysql': ['mysql_command'],
            'has_mssql': ['mssql_command'],
            'has_sip': ['sip_method'],
            'has_tftp': ['tftp_file'],
            'has_upnp': ['upnp_method'],
            'has_memcache': ['memcache_command'],
            'has_mqtt': ['mqtt_topic'],
            'has_epmap': ['epmap_uuid'],
        }
        
        for feature_name, keys in protocol_map.items():
            features[feature_name] = 1 if any(k in meta and meta[k] for k in keys) else 0
        
        # Count protocols
        features['protocol_count'] = sum(v for k, v in features.items() if k.startswith('has_'))
        
        # Content features
        features['http_url_length'] = len(meta.get('http_url', ''))
        features['http_url_entropy'] = self._calculate_entropy(meta.get('http_url', ''))
        features['has_http_url'] = 1 if meta.get('http_url') else 0
        
        features['http_ua_length'] = len(meta.get('http_user_agent', ''))
        
        features['smb_file_length'] = len(meta.get('smb_file', ''))
        features['has_smb_file'] = 1 if meta.get('smb_file') else 0
        
        features['ftp_cmd_length'] = len(meta.get('ftp_command', ''))
        features['ftp_cmd_entropy'] = self._calculate_entropy(meta.get('ftp_command', ''))
        features['has_ftp_command'] = 1 if meta.get('ftp_command') else 0
        
        # Malware indicators
        features['has_download'] = 1 if meta.get('dionaea_download_url') else 0
        features['download_url_length'] = len(meta.get('dionaea_download_url', ''))
        features['has_known_file_type'] = 1 if meta.get('dionaea_file_type') not in [None, 'unknown'] else 0
        features['file_size'] = meta.get('dionaea_file_size', 0) or 0
        
        # P0f features
        features['has_p0f_os'] = 1 if meta.get('p0f_os') else 0
        features['p0f_uptime'] = meta.get('p0f_uptime', 0) or 0
        
        # Connection type
        features['is_tcp'] = 1 if meta.get('connection_transport') == 'tcp' else 0
        features['is_udp'] = 1 if meta.get('connection_transport') == 'udp' else 0
        
        return features
    
    def _vectorize_for_preprocessor(self, features: Dict) -> list:
        """Convert feature dict to array matching preprocessor feature order"""
        if not hasattr(self, 'preprocessor') or not self.preprocessor:
            return list(features.values())
        
        # Return features in the order preprocessor expects
        ordered = []
        for name in self.preprocessor.feature_names:
            ordered.append(features.get(name, 0.0))
        return ordered

    def _map_category_to_attack_type(self, category_id: int) -> AttackType:
        """Map numeric category to AttackType enum"""
        # This should match your training labels
        mapping = {
            0: AttackType.RECONNAISSANCE,
            1: AttackType.EXPLOITATION,
            2: AttackType.MALWARE,
            3: AttackType.BRUTE_FORCE,
            4: AttackType.DENIAL_OF_SERVICE,
            5: AttackType.PRIVILEGE_ESCALATION,
            6: AttackType.LATERAL_MOVEMENT,
            7: AttackType.EXFILTRATION,
        }
        return mapping.get(category_id, AttackType.UNKNOWN)

    def _infer_attack_type_from_features(self, features: Dict) -> AttackType:
        """Infer attack type from feature patterns"""
        if features.get('has_download', 0) > 0 or features.get('has_known_file_type', 0) > 0:
            return AttackType.MALWARE
        if features.get('has_ftp_command', 0) > 0 and features.get('ftp_cmd_entropy', 0) > 3:
            return AttackType.EXFILTRATION
        if features.get('protocol_count', 0) > 3:
            return AttackType.RECONNAISSANCE
        if features.get('is_night', 0) > 0 and features.get('has_http', 0) > 0:
            return AttackType.BRUTE_FORCE
        return AttackType.UNKNOWN

    def _calculate_threat_level(self, confidence: float, anomaly_score: float, attack_type: AttackType) -> ThreatLevel:
        """Calculate threat level from scores"""
        combined_score = (confidence + anomaly_score) / 2
        
        if attack_type in [AttackType.MALWARE, AttackType.EXFILTRATION] and combined_score > 0.8:
            return ThreatLevel.CRITICAL
        elif combined_score > 0.85:
            return ThreatLevel.CRITICAL
        elif combined_score > 0.7:
            return ThreatLevel.HIGH
        elif combined_score > 0.5:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
