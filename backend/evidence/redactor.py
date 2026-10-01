import re
from typing import Dict, Any, Union

class Redactor:
    # Basic patterns for JWTs and secrets
    JWT_PATTERN = re.compile(r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*')
    CREDENTIAL_KEYS = ["password", "secret", "token", "api_key", "authorization", "cookie", "session"]
    
    @classmethod
    def redact_string(cls, text: str) -> str:
        if not isinstance(text, str):
            return text
        
        # Redact JWTs
        redacted = cls.JWT_PATTERN.sub("[REDACTED_JWT]", text)
        return redacted

    @classmethod
    def redact_dict(cls, data: Union[Dict[str, Any], list, str, Any]) -> Any:
        if isinstance(data, dict):
            redacted = {}
            for k, v in data.items():
                lower_k = k.lower()
                # If key looks like a credential, redact entirely
                if any(cred in lower_k for cred in cls.CREDENTIAL_KEYS):
                    redacted[k] = "[REDACTED_CREDENTIAL]"
                else:
                    redacted[k] = cls.redact_dict(v)
            return redacted
        elif isinstance(data, list):
            return [cls.redact_dict(item) for item in data]
        elif isinstance(data, str):
            return cls.redact_string(data)
        else:
            return data
