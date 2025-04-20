import re
import json
import numpy as np
from urllib.parse import unquote

class WAFCore:
    def __init__(self):
        """Initialize the WAF core with attack patterns and rules"""
        # SQL Injection patterns
        self.sqli_patterns = [
            r"(?i)('|\").*?(\s|\+)*(OR|AND)(\s|\+)*('|\"|[0-9])",  # Basic OR/AND
            r"(?i)(\%27|')(\s|\+)*(OR|AND)(\s|\+)*('|\"|[0-9])",   # URL encoded
            r"(?i)(\-\-|\#|\;)",                                   # SQL comments
            r"(?i)(UNION(\s|\+)*SELECT)",                          # UNION SELECT
            r"(?i)(SELECT(\s|\+)*FROM)",                           # SELECT FROM
            r"(?i)(INSERT(\s|\+)*INTO)",                           # INSERT INTO
            r"(?i)(DROP(\s|\+)*TABLE)",                            # DROP TABLE
            r"(?i)(ALTER(\s|\+)*TABLE)",                           # ALTER TABLE
            r"(?i)(EXEC(\s|\+)*\(?XP_)",                           # SQL Server stored procedures
            r"(?i)(LOAD_FILE\()",                                  # MySQL file access
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"(?i)(<script[^>]*>.*?</script>)",                    # Basic script tags
            r"(?i)(javascript:)",                                  # JavaScript protocol
            r"(?i)(onload=|onerror=|onmouseover=|onclick=)",       # Event handlers
            r"(?i)(<img[^>]*src=[^>]*>)",                          # Image tags
            r"(?i)(<iframe[^>]*src=[^>]*>)",                       # iframes
            r"(?i)(alert\(|confirm\(|prompt\()",                   # JavaScript functions
            r"(?i)(eval\(|setTimeout\(|setInterval\()",            # JavaScript eval
            r"(?i)(document\.cookie)",                             # Cookie access
            r"(?i)(document\.location)",                           # Location manipulation
            r"(?i)(String\.fromCharCode\()",                       # Character code conversion
        ]
        
        # Path Traversal patterns
        self.path_traversal_patterns = [
            r"(?i)(\.\.\/)",                                       # Basic directory traversal
            r"(?i)(%2e%2e%2f)",                                    # URL encoded ../ 
            r"(?i)(%252e%252e%252f)",                              # Double URL encoded ../
            r"(?i)(\.\.\\)",                                       # Windows path traversal
            r"(?i)(%2e%2e\\)",                                     # URL encoded ..\
            r"(?i)(\.\.%2f)",                                      # Mixed encoding ../
            r"(?i)(/etc/passwd)",                                  # Linux password file
            r"(?i)(c:\\windows\\win.ini)",                         # Windows ini file
            r"(?i)(/windows/win.ini)",                             # Windows ini alternative
            r"(?i)(/boot.ini)",                                    # Windows boot.ini
        ]
        
        # Command Injection patterns
        self.command_injection_patterns = [
            r"(?i)(;|\||\|\||&&)(\s*)(cat|ls|pwd|whoami|id|uname|echo)",  # Basic command chaining
            r"(?i)(;|\||\|\||&&)(\s*)(type|dir|copy|del|echo)",           # Windows commands
            r"(?i)(`.*?`)",                                               # Backtick execution
            r"(?i)(\$\(.*?\))",                                           # Command substitution
            r"(?i)(system\(|exec\(|shell_exec\(|passthru\(|eval\()",      # PHP functions
            r"(?i)(ping(\s|\+)+-(\s|\+)+c(\s|\+)+[0-9])",                 # Ping command
            r"(?i)(nc|netcat|ncat)(\s|\+)+-(\s|\+)+(e|c)(\s|\+)+",        # Netcat
            r"(?i)(wget|curl)(\s|\+)+-(\s|\+)+O",                         # wget/curl
            r"(?i)(/dev/tcp/)",                                           # Bash TCP
            r"(?i)(python(\s|\+)+-c)",                                    # Python execution
        ]
        
        # Local File Inclusion patterns
        self.lfi_patterns = [
            r"(?i)(php://filter/)",                                       # PHP filter
            r"(?i)(php://input)",                                         # PHP input
            r"(?i)(data://text/plain)",                                   # Data URI
            r"(?i)(zip://|phar://)",                                      # Archive wrappers
            r"(?i)(file://)",                                             # File URI
            r"(?i)(/proc/self/)",                                         # Proc filesystem
            r"(?i)(/var/log/)",                                           # Log files
            r"(?i)(/etc/)",                                               # Configuration files
            r"(?i)(c:\\windows\\)",                                       # Windows directory
            r"(?i)(%00)",                                                 # Null byte
        ]
        
        # Combine all patterns
        self.all_patterns = {
            'sql_injection': self.sqli_patterns,
            'xss': self.xss_patterns,
            'path_traversal': self.path_traversal_patterns,
            'command_injection': self.command_injection_patterns,
            'lfi': self.lfi_patterns
        }
        
        # Sensitive paths
        self.sensitive_paths = [
            r"(?i)(/admin)",
            r"(?i)(/login)",
            r"(?i)(/wp-admin)",
            r"(?i)(/phpmyadmin)",
            r"(?i)(/config)",
            r"(?i)(/backup)",
            r"(?i)(/api/v[0-9]+)",
        ]
        
        # Initialize feature data for anomaly detection
        self.feature_data = []
        
    def analyze_request(self, method, path, payload):
        """
        Analyze a request to determine if it contains an attack
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            path (str): Request path
            payload (dict): Dictionary containing params, body, and headers
            
        Returns:
            tuple: (attack_type, is_blocked)
        """
        # URL decode the path
        decoded_path = unquote(path)
        
        # Convert payload to string for analysis
        payload_str = json.dumps(payload)
        
        # Check for attacks in path and payload
        for attack_type, patterns in self.all_patterns.items():
            for pattern in patterns:
                # Check path
                if re.search(pattern, decoded_path):
                    return attack_type, True
                
                # Check payload
                if re.search(pattern, payload_str):
                    return attack_type, True
        
        # Check for sensitive paths
        for pattern in self.sensitive_paths:
            if re.search(pattern, decoded_path):
                # For sensitive paths, we don't block but we mark it as a potential risk
                return 'sensitive_path', False
        
        # If no attack is detected, return 'none' and don't block
        return 'none', False
    
    def extract_features(self, method, path, payload):
        """
        Extract numerical features from a request for anomaly detection
        
        Args:
            method (str): HTTP method
            path (str): Request path
            payload (dict): Request payload
            
        Returns:
            list: Numerical features
        """
        # Convert payload to string
        payload_str = json.dumps(payload)
        
        # Feature 1: Path length
        path_length = len(path)
        
        # Feature 2: Payload length
        payload_length = len(payload_str)
        
        # Feature 3: Number of parameters
        num_params = len(payload.get('params', {}))
        
        # Feature 4: Number of special characters in path
        special_chars_path = sum(1 for c in path if not c.isalnum() and c not in '/-_.')
        
        # Feature 5: Number of special characters in payload
        special_chars_payload = sum(1 for c in payload_str if not c.isalnum() and c not in '/-_.')
        
        # Feature 6: Method type (convert to numerical)
        method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3, 'PATCH': 4, 'OPTIONS': 5}
        method_num = method_map.get(method, 0)
        
        # Feature 7: Number of sensitive keywords in path and payload
        sensitive_keywords = ['admin', 'login', 'password', 'token', 'key', 'secret', 'config', 'root', 'shell']
        num_sensitive = sum(1 for keyword in sensitive_keywords if keyword.lower() in path.lower() or keyword.lower() in payload_str.lower())
        
        # Feature 8: Number of numeric characters in path
        num_numeric_path = sum(1 for c in path if c.isdigit())
        
        # Feature 9: Number of numeric characters in payload
        num_numeric_payload = sum(1 for c in payload_str if c.isdigit())
        
        # Feature 10: Path depth (number of directories)
        path_depth = len([p for p in path.split('/') if p])
        
        return [
            path_length, 
            payload_length, 
            num_params, 
            special_chars_path, 
            special_chars_payload, 
            method_num, 
            num_sensitive, 
            num_numeric_path, 
            num_numeric_payload, 
            path_depth
        ]
    
    def train_anomaly_detection(self, features):
        """
        Add features to the training data for anomaly detection
        
        Args:
            features (list): Feature vector extracted from a request
        """
        self.feature_data.append(features)
    
    def is_anomalous(self, features, model):
        """
        Determine if a request is anomalous using the trained model
        
        Args:
            features (list): Feature vector extracted from a request
            model: Trained anomaly detection model
            
        Returns:
            bool: True if the request is anomalous, False otherwise
        """
        if len(self.feature_data) < 100:
            # Not enough data to make a reliable prediction
            return False
            
        try:
            # Predict using the model
            return model.predict([features])[0] == -1
        except Exception as e:
            print(f"Error in anomaly detection: {e}")
            return False
    
    def generate_attack_payload(self, attack_type):
        """
        Generate a sample attack payload for simulation
        
        Args:
            attack_type (str): Type of attack to simulate
            
        Returns:
            str: Sample attack payload
        """
        if attack_type == 'sql_injection':
            return "' OR 1=1 --"
        elif attack_type == 'xss':
            return "<script>alert('XSS')</script>"
        elif attack_type == 'path_traversal':
            return "../../../etc/passwd"
        elif attack_type == 'command_injection':
            return "; cat /etc/passwd"
        elif attack_type == 'lfi':
            return "php://filter/convert.base64-encode/resource=index.php"
        else:
            return "Invalid attack type"
