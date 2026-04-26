from fastapi import HTTPException, status

class VaultAPIException(Exception):
    """Base exception for Vault API."""
    def __init__(self, message: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class SecretNotFoundError(VaultAPIException):
    """Raised when a secret is not found."""
    def __init__(self, message: str = "Secret not found"):
        super().__init__(message, status.HTTP_404_NOT_FOUND)

class ProjectNotFoundError(VaultAPIException):
    """Raised when a project is not found."""
    def __init__(self, message: str = "Project not found"):
        super().__init__(message, status.HTTP_404_NOT_FOUND)

class UnauthorizedError(VaultAPIException):
    """Raised when user is not authorized."""
    def __init__(self, message: str = "Unauthorized"):
        super().__init__(message, status.HTTP_401_UNAUTHORIZED)

class ForbiddenError(VaultAPIException):
    """Raised when user doesn't have permission."""
    def __init__(self, message: str = "Forbidden"):
        super().__init__(message, status.HTTP_403_FORBIDDEN)

class SecretLimitExceededError(VaultAPIException):
    """Raised when user exceeds secret limit for their plan."""
    def __init__(self, message: str = "Secret limit exceeded for your plan"):
        super().__init__(message, status.HTTP_402_PAYMENT_REQUIRED)

class ProjectLimitExceededError(VaultAPIException):
    """Raised when user exceeds project limit for their plan."""
    def __init__(self, message: str = "Project limit exceeded for your plan"):
        super().__init__(message, status.HTTP_402_PAYMENT_REQUIRED)

class InvalidSecretValueError(VaultAPIException):
    """Raised when secret value is invalid."""
    def __init__(self, message: str = "Invalid secret value"):
        super().__init__(message, status.HTTP_400_BAD_REQUEST)

class DuplicateSecretError(VaultAPIException):
    """Raised when trying to create a secret/project with duplicate key/name."""
    def __init__(self, message: str = "Resource with this identifier already exists"):
        super().__init__(message, status.HTTP_409_CONFLICT)

class EncryptionError(VaultAPIException):
    """Raised when encryption/decryption fails."""
    def __init__(self, message: str = "Encryption operation failed"):
        super().__init__(message, status.HTTP_500_INTERNAL_SERVER_ERROR)

class RateLimitError(VaultAPIException):
    """Raised when rate limit is exceeded."""
    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = 60):
        super().__init__(message, status.HTTP_429_TOO_MANY_REQUESTS)
        self.retry_after = retry_after