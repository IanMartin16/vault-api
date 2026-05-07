from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
import structlog

from app.api.deps import get_db, get_current_user_only
from app.models.user import User
from app.schemas.project import ProjectCreate, ProjectUpdate, ProjectResponse
from app.services.project_service import ProjectService
from app.core.exceptions import (
    ProjectNotFoundError,
    DuplicateProjectError,
    ProjectLimitExceededError
)

router = APIRouter()
logger = structlog.get_logger()


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    project: ProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_only)
):
    """
    Create a new project.
    
    Projects organize your secrets by environment (dev, staging, prod, etc.).
    Each project gets its own encryption key derived from the master key.
    
    **Limits by plan:**
    - Free: 2 projects
    - Starter: 10 projects
    - Pro/Enterprise: Unlimited
    """
    service = ProjectService(db)
    
    try:
        new_project = await service.create_project(project, current_user)
        logger.info(
            "project_created",
            project_id=str(new_project.id),
            user_id=str(current_user.id),
            name=new_project.name
        )
        return new_project
    
    except (DuplicateProjectError, ProjectLimitExceededError) as e:
        # Expected errors: safe to show message
        logger.warning(
            "project_creation_failed",
            error_type=type(e).__name__,
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=e.status_code,
            detail=str(e)
        )
    
    except Exception as e:
        # Unexpected errors: log but don't expose details
        logger.error(
            "project_creation_error",
            error_type=type(e).__name__,
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the project. Please try again."
        )


@router.get("", response_model=list[ProjectResponse])
async def list_projects(
    skip: int = Query(0, ge=0, description="Number of projects to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Max number of projects to return"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_only)
):
    """
    List all projects for the current user.
    
    Returns projects ordered by creation date (newest first).
    Includes a count of secrets in each project.
    """
    service = ProjectService(db)
    projects = await service.list_user_projects(current_user.id, skip, limit)
    return projects


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_only)
):
    """
    Get a specific project by ID.
    
    Returns project details including secret count.
    """
    service = ProjectService(db)
    project = await service.get_project_by_id(project_id, current_user.id)
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )
    
    return project


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: UUID,
    project_data: ProjectUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_only)
):
    """
    Update a project.
    
    Only the project owner can update it.
    All fields are optional - only provided fields will be updated.
    """
    service = ProjectService(db)
    
    try:
        updated_project = await service.update_project(
            project_id,
            project_data,
            current_user.id
        )
        logger.info(
            "project_updated",
            project_id=str(project_id),
            user_id=str(current_user.id)
        )
        return updated_project
    
    except (ProjectNotFoundError, DuplicateProjectError) as e:
        # Expected errors: safe to show message
        logger.warning(
            "project_update_failed",
            error_type=type(e).__name__,
            project_id=str(project_id),
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=e.status_code,
            detail=str(e)
        )
    
    except Exception as e:
        # Unexpected errors: log but don't expose details
        logger.error(
            "project_update_error",
            error_type=type(e).__name__,
            project_id=str(project_id),
            user_id=str(current_user.id)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating the project. Please try again."
        )


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_only)
):
    """
    Delete a project.
    
    **WARNING**: This will permanently delete the project and ALL its secrets.
    This action cannot be undone.
    
    Only the project owner can delete it.
    """
    service = ProjectService(db)
    
    deleted = await service.delete_project(project_id, current_user.id)
    
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )
    
    logger.warning(
        "project_deleted",
        project_id=str(project_id),
        user_id=str(current_user.id)
    )