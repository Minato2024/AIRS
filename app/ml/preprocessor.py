"""
Dionaea Honeypot Log Preprocessor
Converts raw Dionaea CSV logs to ML-ready features for AIRS
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
import math
from collections import Counter
from sklearn.preprocessing import LabelEncoder, StandardScaler, OneHotEncoder
from sklearn.model_selection import train_test_split
import joblib
import structlog

logger = structlog.get_logger("airs.ml.preprocessor")


class DionaeaPreprocessor:
    """
    Preprocess Dionaea honeypot logs for machine learning training.
    Handles feature engineering, encoding, and scaling.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.scaler = StandardScaler()
        self.feature_names: List[str] = []
        self.is_fitted = False
        
        # Protocol mapping for feature extraction
        self.protocol_columns = {
            'http': ['http_method', 'http_url', 'http_user_agent', 'http_host'],
            'smb': ['smb_version', 'smb_command', 'smb_share', 'smb_file', 'smb_native_os'],
            'ftp': ['ftp_user', 'ftp_password', 'ftp_command', 'ftp_arg'],
            'mysql': ['mysql_status', 'mysql_command'],
            'mssql': ['mssql_status', 'mssql_command'],
            'sip': ['sip_method', 'sip_user_agent', 'sip_call_id', 'sip_from', 'sip_to'],
            'tftp': ['tftp_file', 'tftp_opcode', 'tftp_transfer_type'],
            'upnp': ['upnp_method', 'upnp_url', 'upnp_user_agent'],
            'memcache': ['memcache_command', 'memcache_key'],
            'mqtt': ['mqtt_topic', 'mqtt_message'],
            'epmap': ['epmap_uuid', 'epmap_annotation']
        }
        
    def load_data(self, filepath: str) -> pd.DataFrame:
        """Load Dionaea dataset from CSV"""
        logger.info("Loading Dionaea dataset", filepath=filepath)
        
        try:
            df = pd.read_csv(filepath)
            logger.info("Dataset loaded", rows=len(df), columns=len(df.columns))
            return df
        except Exception as e:
            logger.error("Failed to load dataset", error=str(e))
            raise
    
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and validate raw data"""
        logger.info("Cleaning data")
        
        # Remove rows with missing critical fields
        critical_cols = ['connection_timestamp', 'remote_host', 'label']
        df = df.dropna(subset=critical_cols)
        
        # Handle duplicates
        initial_rows = len(df)
        df = df.drop_duplicates()
        logger.info("Removed duplicates", count=initial_rows - len(df))
        
        # Convert timestamp
        df['timestamp'] = pd.to_datetime(df['connection_timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])
        
        return df
    
    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract and engineer features from raw Dionaea logs"""
        logger.info("Engineering features")
        
        features = pd.DataFrame(index=df.index)
        
        # ========== TEMPORAL FEATURES ==========
        features['hour'] = df['timestamp'].dt.hour
        features['day_of_week'] = df['timestamp'].dt.dayofweek
        features['is_weekend'] = (features['day_of_week'] >= 5).astype(int)
        features['is_night'] = ((features['hour'] < 6) | (features['hour'] > 22)).astype(int)
        
        # ========== NETWORK FEATURES ==========
        # Parse IP addresses
        features['remote_ip_octet_1'] = df['remote_host'].str.split('.').str[0].fillna(0).astype(int)
        features['remote_ip_octet_2'] = df['remote_host'].str.split('.').str[1].fillna(0).astype(int)
        features['remote_ip_octet_3'] = df['remote_host'].str.split('.').str[2].fillna(0).astype(int)
        features['remote_ip_octet_4'] = df['remote_host'].str.split('.').str[3].fillna(0).astype(int)
        
        # Port features
        features['remote_port'] = df['remote_port'].fillna(0).astype(int)
        features['local_port'] = df['local_port'].fillna(0).astype(int)
        features['is_common_port'] = features['remote_port'].isin([22, 80, 443, 21, 25, 3306, 5432]).astype(int)
        
        # ========== PROTOCOL INDICATORS ==========
        # Check which protocol columns are present
        for protocol, cols in self.protocol_columns.items():
            present_cols = [c for c in cols if c in df.columns]
            if present_cols:
                # Protocol is present if any of its columns are non-null
                features[f'has_{protocol}'] = df[present_cols].notna().any(axis=1).astype(int)
            else:
                features[f'has_{protocol}'] = 0
        
        # Total protocol count
        protocol_indicator_cols = [c for c in features.columns if c.startswith('has_')]
        features['protocol_count'] = features[protocol_indicator_cols].sum(axis=1)
        
        # ========== PAYLOAD/CONTENT FEATURES ==========
        # HTTP features
        if 'http_url' in df.columns:
            features['http_url_length'] = df['http_url'].str.len().fillna(0)
            features['http_url_entropy'] = df['http_url'].apply(self._calculate_entropy)
            features['has_http_url'] = df['http_url'].notna().astype(int)
        
        if 'http_user_agent' in df.columns:
            features['http_ua_length'] = df['http_user_agent'].str.len().fillna(0)
            features['http_ua_entropy'] = df['http_user_agent'].apply(self._calculate_entropy)
        
        # SMB features
        if 'smb_file' in df.columns:
            features['smb_file_length'] = df['smb_file'].str.len().fillna(0)
            features['has_smb_file'] = df['smb_file'].notna().astype(int)
        
        # FTP features
        if 'ftp_command' in df.columns:
            features['ftp_cmd_length'] = df['ftp_command'].str.len().fillna(0)
            features['ftp_cmd_entropy'] = df['ftp_command'].apply(self._calculate_entropy)
            features['has_ftp_command'] = df['ftp_command'].notna().astype(int)
        
        # ========== MALWARE/FILE FEATURES ==========
        if 'dionaea_download_url' in df.columns:
            features['has_download'] = df['dionaea_download_url'].notna().astype(int)
            features['download_url_length'] = df['dionaea_download_url'].str.len().fillna(0)
        
        if 'dionaea_file_type' in df.columns:
            features['has_known_file_type'] = (df['dionaea_file_type'] != 'unknown').astype(int)
        
        if 'dionaea_file_size' in df.columns:
            features['file_size'] = df['dionaea_file_size'].fillna(0)
        
        # ========== P0F OS FINGERPRINTING ==========
        if 'p0f_os' in df.columns:
            features['has_p0f_os'] = df['p0f_os'].notna().astype(int)
            features['p0f_uptime'] = df['p0f_uptime'].fillna(0)
        
        # ========== BLACKHOLE/MIRROR DATA ==========
        if 'blackhole_data' in df.columns:
            features['has_blackhole_data'] = df['blackhole_data'].notna().astype(int)
        
        if 'mirror_data' in df.columns:
            features['has_mirror_data'] = df['mirror_data'].notna().astype(int)
        
        # ========== CONNECTION METADATA ==========
        if 'connection_transport' in df.columns:
            features['is_tcp'] = (df['connection_transport'] == 'tcp').astype(int)
            features['is_udp'] = (df['connection_transport'] == 'udp').astype(int)
        
        # Store feature names
        self.feature_names = [c for c in features.columns if c not in ['timestamp']]
        
        logger.info("Feature engineering complete", feature_count=len(self.feature_names))
        
        return features
    
    def _calculate_entropy(self, text: Any) -> float:
        """Calculate Shannon entropy for text"""
        if pd.isna(text) or not str(text):
            return 0.0
        
        text = str(text)
        if len(text) == 0:
            return 0.0
        
        counts = Counter(text)
        length = len(text)
        
        try:
            entropy = -sum((count/length) * math.log2(count/length) for count in counts.values())
            return entropy
        except:
            return 0.0
    
    def prepare_labels(self, df: pd.DataFrame) -> Tuple[pd.Series, pd.Series, pd.Series]:
        """Prepare labels for training"""
        logger.info("Preparing labels")
        
        # Binary label (0 = normal, 1 = attack)
        y_binary = df['label'].astype(int)
        
        # Attack category
        y_category = df.get('attack_cat', pd.Series(['unknown'] * len(df)))
        
        # Threat level
        y_threat = df.get('threat_level', pd.Series(['low'] * len(df)))
        
        # Encode categorical labels
        if 'attack_cat' in df.columns:
            if 'attack_cat' not in self.label_encoders:
                self.label_encoders['attack_cat'] = LabelEncoder()
                y_category_encoded = self.label_encoders['attack_cat'].fit_transform(y_category)
            else:
                y_category_encoded = self.label_encoders['attack_cat'].transform(y_category)
        else:
            y_category_encoded = y_category
        
        return y_binary, pd.Series(y_category_encoded), y_threat
    
    def fit_transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, pd.Series, pd.Series, pd.Series]:
        """Fit preprocessor and transform data"""
        logger.info("Fitting preprocessor")
        
        # Clean and engineer features
        df_clean = self.clean_data(df)
        X_features = self.engineer_features(df_clean)
        
        # Prepare labels
        y_binary, y_category, y_threat = self.prepare_labels(df_clean)
        
        # Select only numeric features for scaling
        X_numeric = X_features[self.feature_names].fillna(0)
        
        # Fit scaler
        X_scaled = self.scaler.fit_transform(X_numeric)
        self.is_fitted = True
        
        logger.info("Preprocessor fitted", samples=len(X_scaled), features=X_scaled.shape[1])
        
        return X_scaled, y_binary, y_category, y_threat
    
    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transform new data using fitted preprocessor"""
        if not self.is_fitted:
            raise ValueError("Preprocessor must be fitted before transform")
        
        df_clean = self.clean_data(df)
        X_features = self.engineer_features(df_clean)
        X_numeric = X_features[self.feature_names].fillna(0)
        X_scaled = self.scaler.transform(X_numeric)
        
        return X_scaled
    
    def save(self, filepath: str):
        """Save preprocessor state"""
        joblib.dump({
            'label_encoders': self.label_encoders,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_fitted': self.is_fitted,
            'protocol_columns': self.protocol_columns
        }, filepath)
        logger.info("Preprocessor saved", filepath=filepath)
    
    def load(self, filepath: str):
        """Load preprocessor state"""
        state = joblib.load(filepath)
        self.label_encoders = state['label_encoders']
        self.scaler = state['scaler']
        self.feature_names = state['feature_names']
        self.is_fitted = state['is_fitted']
        self.protocol_columns = state['protocol_columns']
        logger.info("Preprocessor loaded", filepath=filepath)


def create_train_test_split(
    X: np.ndarray, 
    y_binary: pd.Series, 
    y_category: pd.Series,
    test_size: float = 0.2,
    random_state: int = 42
) -> Tuple:
    """Create stratified train/test split"""
    # First split: separate test set
    X_train_val, X_test, y_bin_train_val, y_bin_test, y_cat_train_val, y_cat_test = train_test_split(
        X, y_binary, y_category,
        test_size=test_size,
        random_state=random_state,
        stratify=y_binary
    )
    
    # Second split: separate validation from train
    val_size = test_size / (1 - test_size)  # Adjust for remaining data
    X_train, X_val, y_bin_train, y_bin_val, y_cat_train, y_cat_val = train_test_split(
        X_train_val, y_bin_train_val, y_cat_train_val,
        test_size=val_size,
        random_state=random_state,
        stratify=y_bin_train_val
    )
    
    return (
        X_train, X_val, X_test,
        y_bin_train, y_bin_val, y_bin_test,
        y_cat_train, y_cat_val, y_cat_test
    )