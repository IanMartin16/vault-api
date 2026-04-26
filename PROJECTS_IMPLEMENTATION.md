# 📦 Implementación de Projects CRUD

## 🎯 Objetivo

Implementar el sistema de Proyectos que permitirá a los usuarios organizar sus secretos en contenedores lógicos (dev, staging, production, etc.).

---

## 📋 Endpoints a Implementar

```
POST   /api/v1/projects          - Crear proyecto
GET    /api/v1/projects          - Listar proyectos del usuario
GET    /api/v1/projects/{id}     - Ver proyecto específico
PUT    /api/v1/projects/{id}     - Actualizar proyecto
DELETE /api/v1/projects/{id}     - Eliminar proyecto (soft delete)
```

---

## 🔧 Implementación

### 1. ProjectService (app/services/project_service.py)

Crear archivo nuevo con la lógica de negocio de proyectos.

### 2. Actualizar app/api/v1/projects.py

Implementar todos los endpoints con sus validaciones.

### 3. Validaciones de Negocio

- Usuario no puede exceder el límite de proyectos de su plan
- Proyectos deben tener nombre único por usuario
- Al crear proyecto, generar DEK salt automáticamente
- Solo el owner puede modificar/eliminar el proyecto

---

## 🧪 Testing

### Flujo de Prueba

1. Login para obtener token
2. Crear proyecto "Development"
3. Crear proyecto "Production"  
4. Listar proyectos
5. Actualizar proyecto
6. Intentar crear más proyectos que el límite (debe fallar)
7. Eliminar proyecto

### Comandos PowerShell

```powershell
# 1. Login (si no tienes token guardado)
$tokens = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" `
    -Method Post -ContentType "application/json" `
    -Body (@{email="martin@evilink.com"; password="SecurePass123"} | ConvertTo-Json)
$token = $tokens.access_token

# 2. Crear proyecto Development
$devProject = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/projects" `
    -Method Post `
    -Headers @{Authorization="Bearer $token"} `
    -ContentType "application/json" `
    -Body (@{
        name="Development"
        description="Development environment secrets"
        environment="development"
        color="#10B981"
    } | ConvertTo-Json)

$devProjectId = $devProject.id
Write-Host "Development Project ID: $devProjectId"

# 3. Crear proyecto Production
$prodProject = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/projects" `
    -Method Post `
    -Headers @{Authorization="Bearer $token"} `
    -ContentType "application/json" `
    -Body (@{
        name="Production"
        description="Production environment secrets"
        environment="production"
        color="#EF4444"
    } | ConvertTo-Json)

# 4. Listar todos los proyectos
$projects = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/projects" `
    -Headers @{Authorization="Bearer $token"}

Write-Host "`nMis Proyectos:"
$projects | Format-Table name, environment, created_at

# 5. Ver proyecto específico
$project = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/projects/$devProjectId" `
    -Headers @{Authorization="Bearer $token"}

# 6. Actualizar proyecto
$updated = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/projects/$devProjectId" `
    -Method Put `
    -Headers @{Authorization="Bearer $token"} `
    -ContentType "application/json" `
    -Body (@{
        description="Updated: Development environment"
        color="#3B82F6"
    } | ConvertTo-Json)

# 7. Eliminar proyecto
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/projects/$devProjectId" `
    -Method Delete `
    -Headers @{Authorization="Bearer $token"}

Write-Host "`n✅ Proyecto eliminado"
```

---

## 📊 Verificación en Base de Datos

```bash
# Ver proyectos creados
docker-compose exec db psql -U vault_user -d vault_db -c "
SELECT id, name, environment, owner_id, created_at 
FROM projects 
ORDER BY created_at DESC;
"

# Ver con información del usuario
docker-compose exec db psql -U vault_user -d vault_db -c "
SELECT 
    p.id,
    p.name,
    p.environment,
    u.email as owner_email,
    p.created_at
FROM projects p
JOIN users u ON p.owner_id = u.id
ORDER BY p.created_at DESC;
"
```

---

## ✅ Checklist de Implementación

- [ ] Crear `app/services/project_service.py`
- [ ] Implementar `create_project()`
- [ ] Implementar `list_user_projects()`
- [ ] Implementar `get_project_by_id()`
- [ ] Implementar `update_project()`
- [ ] Implementar `delete_project()` (soft delete)
- [ ] Actualizar `app/api/v1/projects.py` con todos los endpoints
- [ ] Validar límites de plan (free: 2 proyectos)
- [ ] Validar ownership en update/delete
- [ ] Generar DEK salt automáticamente
- [ ] Probar todos los endpoints
- [ ] Verificar audit logs

---

## 🎯 Siguiente: Secrets CRUD

Una vez que Projects esté funcionando, continuaremos con Secrets que:
- Pertenecen a un Project
- Se encriptan con el DEK del proyecto
- Soportan versionado
- Tienen audit trail completo

