import time
from collections import defaultdict
import os
import jwt
from dotenv import load_dotenv


# Simple in-memory rate limiter
class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)

    def check(self, key, limit=10, window=60):
        """Check if request is within rate limit

        Args:
            key: Unique identifier (like IP or username)
            limit: Max requests allowed in time window
            window: Time window in seconds

        Returns:
            bool: True if request is allowed, False if rate limited
        """
        now = time.time()

        # Clean up old requests
        self.requests[key] = [t for t in self.requests[key] if now - t < window]

        # Check if limit exceeded
        if len(self.requests[key]) >= limit:
            return False

        # Add current request
        self.requests[key].append(now)
        return True





load_dotenv()
SECRET = os.getenv("INTERNAL_JWT_SECRET")

def generate_internal_token():
    payload = {
        "iss": "api-gateway",
        "exp": int(time.time()) + 900  # expire dans 5 minutes
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")
