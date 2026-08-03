"""
Testes unitários para as Regras de Negócio e Entidades do Domínio de Ativos e Scanners (M3.4).
GovSec Shield — Domain Layer Unit Tests
"""

from datetime import timezone
from uuid import uuid4

import pytest

from src.asset.domain.asset_groups import AssetCriticality, AssetEnvironment, AssetGroup
from src.asset.domain.discovered_assets import Asset, AssetService, ServiceProtocol
from src.asset.domain.exceptions import (
    AssetDomainError,
    InvalidCVSSError,
    InvalidPortError,
    InvalidStatusTransitionError,
)
from src.asset.domain.monitoring import MonitoringIntegration, MonitoringProvider
from src.asset.domain.scan_executions import ExecutionStatus, ScanExecution
from src.asset.domain.scan_schedules import FrequencyType, ScanSchedule
from src.asset.domain.scan_targets import IPTargetValidator, ScanTarget, TargetType
from src.asset.domain.scanner_profiles import PortStrategy, ScannerProfile
from src.asset.domain.vulnerabilities import (
    VulnerabilityFinding,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)


def test_asset_group_creation_and_invariants():
    tenant_id = uuid4()
    user_id = uuid4()
    group = AssetGroup.create(
        tenant_id=tenant_id,
        name="  Rede Datacenter Principal  ",
        created_by=user_id,
        environment=AssetEnvironment.PRODUCTION,
        criticality=AssetCriticality.HIGH,
    )
    assert group.name == "Rede Datacenter Principal"
    assert group.active is True
    assert group.environment == AssetEnvironment.PRODUCTION
    assert group.criticality == AssetCriticality.HIGH

    group.deactivate(updated_by=user_id)
    assert group.active is False

    with pytest.raises(AssetDomainError):
        AssetGroup.create(tenant_id=tenant_id, name="", created_by=user_id)


def test_ip_target_validator_single_ip():
    res = IPTargetValidator.validate_and_normalize(TargetType.SINGLE_IP, "10.0.1.50")
    assert res.is_valid is True
    assert res.normalized_value == "10.0.1.50"
    assert res.first_ip == "10.0.1.50"
    assert res.last_ip == "10.0.1.50"
    assert res.estimated_addresses == 1


def test_ip_target_validator_cidr():
    res = IPTargetValidator.validate_and_normalize(TargetType.CIDR, "192.168.1.0/24")
    assert res.is_valid is True
    assert res.normalized_value == "192.168.1.0/24"
    assert res.first_ip == "192.168.1.0"
    assert res.last_ip == "192.168.1.255"
    assert res.estimated_addresses == 256


def test_ip_target_validator_ip_range_valid_and_inverted():
    res = IPTargetValidator.validate_and_normalize(
        TargetType.IP_RANGE, "10.10.1.10 - 10.10.1.50"
    )
    assert res.is_valid is True
    assert res.normalized_value == "10.10.1.10-10.10.1.50"
    assert res.first_ip == "10.10.1.10"
    assert res.last_ip == "10.10.1.50"
    assert res.estimated_addresses == 41

    # Intervalo invertido (fim < inicio)
    res_inv = IPTargetValidator.validate_and_normalize(
        TargetType.IP_RANGE, "10.10.1.50 - 10.10.1.10"
    )
    assert res_inv.is_valid is False
    assert "é menor que o IP inicial" in res_inv.error_message


def test_ip_target_validator_public_ip_rejected_by_default():
    res = IPTargetValidator.validate_and_normalize(TargetType.SINGLE_IP, "8.8.8.8")
    assert res.is_valid is False
    assert "público" in res.error_message

    res_allowed = IPTargetValidator.validate_and_normalize(
        TargetType.SINGLE_IP, "8.8.8.8", allow_public_targets=True
    )
    assert res_allowed.is_valid is True
    assert len(res_allowed.security_warnings) > 0


def test_scan_target_creation():
    tenant_id = uuid4()
    group_id = uuid4()
    user_id = uuid4()

    target = ScanTarget.create(
        tenant_id=tenant_id,
        asset_group_id=group_id,
        name="Servidor Web",
        target_type=TargetType.HOSTNAME,
        target_value="servidor.prefeitura.local",
        created_by=user_id,
        authorization_reference="DOC-AUTH-2026-001",
    )
    assert target.target_value == "servidor.prefeitura.local"
    assert target.authorization_reference == "DOC-AUTH-2026-001"


def test_discovered_asset_and_service_validation():
    tenant_id = uuid4()
    group_id = uuid4()

    asset = Asset.create(
        tenant_id=tenant_id,
        asset_group_id=group_id,
        ip_address="10.0.0.15",
        hostname="router01.local",
        metadata={"token": "secret123", "normal_key": "data"},
    )
    assert asset.ip_address == "10.0.0.15"
    assert asset.metadata["token"] == "[REDACTED]"
    assert asset.metadata["normal_key"] == "data"

    with pytest.raises(AssetDomainError):
        Asset.create(
            tenant_id=tenant_id, asset_group_id=group_id, ip_address="invalid_ip"
        )

    service = AssetService.create(
        tenant_id=tenant_id,
        asset_id=asset.id,
        port=443,
        protocol=ServiceProtocol.TCP,
        banner="Server: Apache/2.4 (password=123)",
    )
    assert service.port == 443
    assert "password=" in service.banner or "[REDACTED]" in service.banner

    with pytest.raises(InvalidPortError):
        AssetService.create(tenant_id=tenant_id, asset_id=asset.id, port=70000)


def test_scanner_profile_creation_and_limits():
    tenant_id = uuid4()
    user_id = uuid4()

    profile = ScannerProfile.create(
        tenant_id=tenant_id,
        name="Perfil Padrão",
        created_by=user_id,
        port_strategy=PortStrategy.CUSTOM,
        custom_ports=[80, 443, 8080],
        timeout_seconds=60,
        max_parallelism=20,
    )
    assert profile.custom_ports == [80, 443, 8080]

    with pytest.raises(AssetDomainError):
        ScannerProfile.create(
            tenant_id=tenant_id,
            name="Perfil Inválido",
            created_by=user_id,
            timeout_seconds=9999,
        )


def test_scan_schedule_creation_and_next_run():
    tenant_id = uuid4()
    user_id = uuid4()
    profile_id = uuid4()
    target_id = uuid4()

    schedule = ScanSchedule.create(
        tenant_id=tenant_id,
        name="Varredura Diária",
        scanner_profile_id=profile_id,
        target_ids=[target_id],
        created_by=user_id,
        frequency_type=FrequencyType.CRON,
        cron_expression="0 2 * * *",
        tz_name="America/Sao_Paulo",
    )
    assert schedule.next_run_at is not None
    assert schedule.next_run_at.tzinfo == timezone.utc

    with pytest.raises(AssetDomainError):
        ScanSchedule.create(
            tenant_id=tenant_id,
            name="Sem Alvos",
            scanner_profile_id=profile_id,
            target_ids=[],
            created_by=user_id,
        )


def test_scan_execution_state_machine():
    tenant_id = uuid4()
    profile_id = uuid4()

    execution = ScanExecution.create(
        tenant_id=tenant_id,
        scanner_profile_id=profile_id,
        targets_total=5,
    )
    assert execution.status == ExecutionStatus.QUEUED

    execution.transition_to(ExecutionStatus.RUNNING)
    assert execution.status == ExecutionStatus.RUNNING
    assert execution.started_at is not None

    execution.transition_to(ExecutionStatus.COMPLETED)
    assert execution.status == ExecutionStatus.COMPLETED
    assert execution.finished_at is not None

    # Transição inválida a partir de um estado terminal
    with pytest.raises(InvalidStatusTransitionError):
        execution.transition_to(ExecutionStatus.RUNNING)


def test_vulnerability_finding_deduplication_and_triage():
    tenant_id = uuid4()
    asset_id = uuid4()
    execution_id = uuid4()
    user_id = uuid4()

    finding = VulnerabilityFinding.create(
        tenant_id=tenant_id,
        asset_id=asset_id,
        scan_execution_id=execution_id,
        title="OpenSSL Outdated",
        cve_id="CVE-2026-9999",
        severity=VulnerabilitySeverity.HIGH,
        cvss_score=8.5,
    )
    assert finding.cve_id == "CVE-2026-9999"
    assert finding.status == VulnerabilityStatus.OPEN
    assert len(finding.deduplication_hash) == 64

    # Aceitar risco sem justificativa deve falhar
    with pytest.raises(AssetDomainError):
        finding.change_status(
            VulnerabilityStatus.ACCEPTED, changed_by=user_id, justification=""
        )

    # Aceitar risco com justificativa deve funcionar e registrar histórico
    history = finding.change_status(
        VulnerabilityStatus.ACCEPTED,
        changed_by=user_id,
        justification="Risco aceito devido a controle compensatório no WAF.",
    )
    assert finding.status == VulnerabilityStatus.ACCEPTED
    assert history.from_status == VulnerabilityStatus.OPEN
    assert history.to_status == VulnerabilityStatus.ACCEPTED

    with pytest.raises(InvalidCVSSError):
        VulnerabilityFinding.create(
            tenant_id=tenant_id,
            asset_id=asset_id,
            scan_execution_id=execution_id,
            title="Erro CVSS",
            severity=VulnerabilitySeverity.LOW,
            cvss_score=15.0,
        )


def test_monitoring_integration_creation():
    tenant_id = uuid4()
    integration = MonitoringIntegration.create(
        tenant_id=tenant_id,
        name="Zabbix Prefeitura",
        base_url="https://zabbix.prefeitura.gov.br/api_jsonrpc.php",
        credential_reference="vault://zabbix/token",
        provider=MonitoringProvider.ZABBIX,
    )
    assert integration.provider == MonitoringProvider.ZABBIX
    assert integration.credential_reference == "vault://zabbix/token"

    with pytest.raises(AssetDomainError):
        MonitoringIntegration.create(
            tenant_id=tenant_id,
            name="Zabbix Erro",
            base_url="ftp://invalid.com",
            credential_reference="secret",
        )
