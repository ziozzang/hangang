//! Cross-store completion acknowledgement. Local intent precedes SQL mutation;
//! SQL evidence precedes the local acknowledgement that permits retention.
use crate::{
    admin_users::{ConfigOperationConflict, ConfigReleaseWork, MutationAuthority, Store},
    config_store::ConfigStore,
};

/// Recover or initiate a release for one durably completed local operation.
/// A caller may retry explicitly with the operation identity after a lost ACK.
/// Neither receipt absence nor a transport failure proves completion.
pub async fn release(
    users: &Store,
    store: &dyn ConfigStore,
    authority: MutationAuthority,
    operation_id: &str,
) -> anyhow::Result<ConfigReleaseWork> {
    anyhow::ensure!(
        store.supports_receipt_release_v2(),
        "receipt release unsupported"
    );
    let operation = users
        .config_operation(operation_id)
        .await?
        .ok_or(ConfigOperationConflict)?;
    if operation.receipt_version != 2
        || operation.state != crate::admin_users::ConfigOperationState::CandidateActivated
    {
        return Err(ConfigOperationConflict.into());
    }
    let receipt = if operation.release_id.is_some() {
        // The durable intent retains the entire tuple even if the original
        // receipt has since been archived and removed by future retention.
        users
            .config_release(operation_id)
            .await?
            .ok_or(ConfigOperationConflict)?
            .receipt
    } else {
        store
            .lookup_commit_receipt_v2(&operation.authority_id, u64::try_from(operation.id)?)
            .await?
            .receipt
            .ok_or(ConfigOperationConflict)?
    };
    // This transaction revalidates live authority and the exact local tuple.
    // It is the durable acceptance boundary; revocation afterwards does not
    // cancel accepted work. No local DB lock spans remote I/O.
    let work = users
        .prepare_config_release_authorized(authority, operation_id, &receipt)
        .await?;
    match store.lookup_receipt_release_v2(&work.release_id).await? {
        Some(evidence) => anyhow::ensure!(evidence == work.receipt, "release evidence mismatch"),
        None => {
            anyhow::ensure!(
                work.state != crate::admin_users::ConfigReleaseState::Acknowledged,
                "acknowledged release evidence is missing"
            );
            store
                .release_commit_receipt_v2(&work.release_id, &work.receipt)
                .await?;
        }
    }
    // SQL's successful mutation return is an acknowledgement. If this local
    // write fails, the retained SQL ledger lets a later explicit retry recover.
    users.acknowledge_config_release(&work).await
}
