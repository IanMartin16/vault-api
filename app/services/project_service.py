from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from uuid import UUID
import base64
import os

from app.models.secret import Project
from app.models.user import User
from app.schemas.project import ProjectCreate, ProjectUpdate
from app.core.config import get_settings
from app.core.exceptions import (
    ProjectNotFoundError,
    ForbiddenError,
    ProjectLimitExceededError,
    DuplicateSecretError
)

settings = get_settings()


class ProjectService:
    """Business logic for project management."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_project(
        self, 
        project_data: ProjectCreate, 
        user: User
    ) -> Project:
        """Create a new project."""
        
        # Check project limit based on user's plan
        await self._check_project_limit(user)
        
        # Check for duplicate project name for this user
        stmt = select(Project).where(
            Project.owner_id == user.id,
            Project.name == project_data.name
        )
        result = await self.db.execute(stmt)
        existing_project = result.scalar_one_or_none()
        
        if existing_project:
            raise DuplicateSecretError(
                f"Project with name '{project_data.name}' already exists"
            )
        
        # Generate DEK salt for this project
        dek_salt = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        # Create project
        project = Project(
            owner_id=user.id,
            name=project_data.name,
            description=project_data.description,
            environment=project_data.environment,
            color=project_data.color,
            dek_salt=dek_salt
        )
        
        self.db.add(project)
        await self.db.commit()
        await self.db.refresh(project)
        
        return project
    
    async def list_user_projects(
        self, 
        user_id: UUID,
        skip: int = 0,
        limit: int = 100
    ) -> List[Project]:
        """List all projects for a user."""
        
        stmt = (
            select(Project)
            .where(Project.owner_id == user_id)
            .order_by(Project.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        
        result = await self.db.execute(stmt)
        projects = result.scalars().all()
        
        # Add secret count to each project
        for project in projects:
            # Count non-deleted secrets
            from app.models.secret import Secret
            count_stmt = select(func.count(Secret.id)).where(
                Secret.project_id == project.id,
                Secret.is_deleted == False
            )
            count_result = await self.db.execute(count_stmt)
            project.secret_count = count_result.scalar() or 0
        
        return projects
    
    async def get_project_by_id(
        self, 
        project_id: UUID, 
        user_id: UUID
    ) -> Optional[Project]:
        """Get a project by ID if user has access."""
        
        stmt = select(Project).where(
            Project.id == project_id,
            Project.owner_id == user_id
        )
        result = await self.db.execute(stmt)
        project = result.scalar_one_or_none()
        
        if not project:
            return None
        
        # Add secret count
        from app.models.secret import Secret
        count_stmt = select(func.count(Secret.id)).where(
            Secret.project_id == project.id,
            Secret.is_deleted == False
        )
        count_result = await self.db.execute(count_stmt)
        project.secret_count = count_result.scalar() or 0
        
        return project
    
    async def update_project(
        self,
        project_id: UUID,
        project_data: ProjectUpdate,
        user_id: UUID
    ) -> Project:
        """Update a project."""
        
        # Get project and verify ownership
        project = await self.get_project_by_id(project_id, user_id)
        
        if not project:
            raise ProjectNotFoundError(f"Project {project_id} not found")
        
        # Update fields if provided
        if project_data.name is not None:
            # Check for duplicate name
            stmt = select(Project).where(
                Project.owner_id == user_id,
                Project.name == project_data.name,
                Project.id != project_id
            )
            result = await self.db.execute(stmt)
            existing = result.scalar_one_or_none()
            
            if existing:
                raise DuplicateSecretError(
                    f"Another project with name '{project_data.name}' already exists"
                )
            
            project.name = project_data.name
        
        if project_data.description is not None:
            project.description = project_data.description
        
        if project_data.environment is not None:
            project.environment = project_data.environment
        
        if project_data.color is not None:
            project.color = project_data.color
        
        await self.db.commit()
        await self.db.refresh(project)
        
        return project
    
    async def delete_project(
        self,
        project_id: UUID,
        user_id: UUID
    ) -> bool:
        """
        Delete a project and all its secrets.
        This is a hard delete with cascade.
        """
        
        # Get project and verify ownership
        project = await self.get_project_by_id(project_id, user_id)
        
        if not project:
            return False
        
        # Delete project (secrets will cascade delete due to FK constraint)
        await self.db.delete(project)
        await self.db.commit()
        
        return True
    
    async def _check_project_limit(self, user: User) -> None:
        """Check if user has reached their project limit."""
        
        # Count current projects
        stmt = select(func.count(Project.id)).where(
            Project.owner_id == user.id
        )
        result = await self.db.execute(stmt)
        project_count = result.scalar() or 0
        
        # Get limit based on plan
        limits = {
            'free': settings.MAX_PROJECTS_FREE,  # 2
            'starter': 10,
            'pro': float('inf'),  # Unlimited
            'enterprise': float('inf')
        }
        
        max_projects = limits.get(user.plan.value, settings.MAX_PROJECTS_FREE)
        
        if project_count >= max_projects:
            raise ProjectLimitExceededError(
                f"You have reached the project limit for your plan ({max_projects} projects). "
                f"Upgrade your plan to create more projects."
            )