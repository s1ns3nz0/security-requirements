# Blast-radius review

> Derived from the reviewed threat graph. This is not proof of implementation or certification.

| Threat | Summary | Tenant scope | Data | Runtime | Control | Recovery | Priority floor | Why | Confidence | Validation |
|---|---|---|---|---|---|---|---|---|---|---|
| T-01 | cross_tenant | subset | tenant_dataset | service | feature | tenant_recovery | medium | review_required | inferred | unreviewed |
| T-02 | cross_tenant | subset | tenant_dataset | service | feature | tenant_recovery | medium | review_required | inferred | unreviewed |
| T-03 | cross_tenant | subset | tenant_dataset | service | feature | tenant_recovery | medium | review_required | inferred | unreviewed |
| T-04 | account_region | all | platform_dataset | account | platform | platform_recovery | high | account_or_region_runtime, all_tenants, platform_control, platform_or_regional_recovery, review_required, shared_or_platform_data | inferred | unreviewed |
| T-05 | account_region | subset | tenant_dataset | region | tenant_operations | tenant_recovery | high | account_or_region_runtime, review_required | inferred | unreviewed |
| T-06 | account_region | all | platform_dataset | account | platform | platform_recovery | high | account_or_region_runtime, all_tenants, platform_control, platform_or_regional_recovery, review_required, shared_or_platform_data | inferred | unreviewed |
| T-07 | account_region | all | platform_dataset | account | platform | platform_recovery | high | account_or_region_runtime, all_tenants, platform_control, platform_or_regional_recovery, review_required, shared_or_platform_data | inferred | unreviewed |
| T-08 | account_region | all | platform_dataset | account | platform | platform_recovery | high | account_or_region_runtime, all_tenants, platform_control, platform_or_regional_recovery, review_required, shared_or_platform_data | inferred | unreviewed |
| T-09 | platform | all | shared_dataset | service | platform | platform_recovery | high | all_tenants, platform_control, platform_or_regional_recovery, review_required, shared_or_platform_data | inferred | unreviewed |
| T-10 | account_region | all | shared_dataset | region | platform | platform_recovery | high | account_or_region_runtime, all_tenants, platform_control, platform_or_regional_recovery, review_required, shared_or_platform_data | inferred | unreviewed |
| T-11 | account_region | all | platform_dataset | account | platform | platform_recovery | high | account_or_region_runtime, all_tenants, platform_control, platform_or_regional_recovery, review_required, shared_or_platform_data | inferred | unreviewed |
| T-12 | platform | all | tenant_dataset | cluster | platform | platform_recovery | high | all_tenants, platform_control, platform_or_regional_recovery, review_required | inferred | unreviewed |
| T-13 | account_region | subset | tenant_dataset | region | tenant_operations | tenant_recovery | high | account_or_region_runtime, review_required | inferred | unreviewed |

## Validation work

- **T-01**: test_cross_tenant_request, verify_tenant_claim_binding
- **T-02**: inspect_dynamodb_policy, test_leading_keys_isolation
- **T-03**: inspect_authorizer_mapping, test_route_tenant_mismatch
- **T-04**: review_management_iam, test_persona_authorization
- **T-05**: review_deletion_change, review_offboarding_runbook
- **T-06**: inspect_event_authorization, test_event_replay
- **T-07**: review_service_quotas, test_onboarding_throttle
- **T-08**: inspect_subprocess_arguments, test_provisioning_validation
- **T-09**: inspect_mapping_role, test_out_of_scope_access
- **T-10**: inspect_log_schema, run_log_redaction_tests
- **T-11**: inspect_pipeline_iam, test_out_of_scope_deploy
- **T-12**: review_ecs_capacity, run_noisy_tenant_test
- **T-13**: review_removal_policies, verify_backup_restore
