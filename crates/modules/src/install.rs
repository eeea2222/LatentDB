//! Installs business-module metadata (object types, workflows, roles) into a
//! tenant. Everything goes through kernel services — modules never touch storage
//! directly.

use crate::roles::business_roles;
use crate::schema::{object_types, workflows};
use latentdb_contracts::AuthContext;
use latentdb_kernel::Kernel;

/// Install all module object types, workflows, and roles into the caller's
/// tenant. Idempotent for workflows (upsert); object types/roles assume a fresh
/// tenant. The caller must be a tenant admin (or system) actor.
pub async fn install(kernel: &Kernel, ctx: &AuthContext) -> latentdb_contracts::Result<()> {
    // Workflows first so object types can reference them.
    for wf in workflows() {
        kernel.create_workflow(ctx, &wf).await?;
    }
    for ot in object_types() {
        kernel.create_object_type(ctx, &ot).await?;
    }
    for role in business_roles() {
        kernel
            .create_role(
                ctx,
                role.key,
                role.name,
                Some(role.description),
                &role.grants,
            )
            .await?;
    }
    Ok(())
}
