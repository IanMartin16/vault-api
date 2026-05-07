"""
Authentication context for tracking how a user authenticated.

This is important for audit logging and authorization decisions.
"""

from dataclasses import dataclass, field
from typing import Optional, Set
from uuid import UUID
from enum import Enum


class AuthMethod(str, Enum):
    """Method used for authentication."""
    JWT = "jwt"
    API_KEY = "api_key"


@dataclass
class AuthContext:
    """
    Authentication context attached to each request.
    
    Tracks:
    - User who made the request
    - How they authenticated (JWT vs API key)
    - Which API key was used (if applicable)
    - Project scope (if API key is scoped to project)
    """
    user_id: UUID
    auth_method: AuthMethod
    api_key_id: Optional[UUID] = None
    api_key_project_id: Optional[UUID] = None  # If API key is scoped to specific project
    scopes: Set[str] = field(default_factory=set)
    
    def is_jwt_auth(self) -> bool:
        """Check if authenticated via JWT."""
        return self.auth_method == AuthMethod.JWT
    
    def is_api_key_auth(self) -> bool:
        """Check if authenticated via API key."""
        return self.auth_method == AuthMethod.API_KEY
    
    def can_access_project(self, project_id: UUID) -> bool:
        """
        Check if this auth context can access the given project.
        
        - JWT: Can access any project owned by user (checked elsewhere)
        - API key without project_id: Can access any project owned by user
        - API key WITH project_id: Can ONLY access that specific project
        """
        if self.is_jwt_auth():
            # JWT can access any project (ownership checked in verify_project_access)
            return True
        
        if self.api_key_project_id is None:
            # API key not scoped to project - can access any project
            return True
        
        # API key scoped to specific project - can only access that project
        return self.api_key_project_id == project_id
    
    def has_scope(self, required_scope: str) -> bool:
        if self.is_jwt_auth():
            return True
        
        return "*" in self.scopes or required_scope in self.scopes