from __future__ import annotations

from queryattest.config import (
    AppSettings,
    load_policy,
    load_semantics,
    resolve_project_path,
)
from queryattest.crypto import KeyMaterial
from queryattest.database import PostgresGateway
from queryattest.identity import EnvironmentPrincipalProvider
from queryattest.policy import PolicyEngine
from queryattest.semantics import SemanticCatalog
from queryattest.service import QueryAttestService
from queryattest.store import EncryptedStateStore
from queryattest.tickets import TicketService


def create_service(settings: AppSettings | None = None) -> QueryAttestService:
    settings = settings or AppSettings()
    settings.validate_runtime()
    policy_path = resolve_project_path(settings.policy_path)
    semantics_path = resolve_project_path(settings.semantics_path)
    state_path = resolve_project_path(settings.state_path)

    policy_config = load_policy(policy_path)
    semantic_config = load_semantics(semantics_path)
    catalog = SemanticCatalog(semantic_config)
    policy = PolicyEngine(policy_config)
    keys = KeyMaterial.from_secret(settings.ticket_secret)
    tickets = TicketService(
        keys,
        max_ttl_seconds=policy_config.limits.ticket_ttl_seconds,
    )
    store = EncryptedStateStore(state_path, keys)
    database = PostgresGateway(
        settings.database_url,
        pool_min_size=settings.db_pool_min_size,
        pool_max_size=settings.db_pool_max_size,
        application_name=settings.application_name,
    )
    principals = EnvironmentPrincipalProvider(settings)
    return QueryAttestService(
        settings=settings,
        policy_config=policy_config,
        catalog=catalog,
        policy=policy,
        tickets=tickets,
        store=store,
        database=database,
        principals=principals,
    )
