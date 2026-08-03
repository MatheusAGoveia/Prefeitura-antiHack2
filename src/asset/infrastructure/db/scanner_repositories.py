"""
Repositórios de Persistência Assíncrona para Perfis, Agendamentos, Execuções, Vulnerabilidades e Zabbix (M3.4).
GovSec Shield — Infrastructure Layer
"""

from decimal import Decimal
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.asset.domain.monitoring import MonitoringIntegration, MonitoringProvider, SyncStatus
from src.asset.domain.scan_executions import ExecutionStatus, ScanExecution, TriggerType
from src.asset.domain.scan_schedules import FrequencyType, OverlapPolicy, ScanSchedule
from src.asset.domain.scanner_profiles import PortStrategy, ScannerProfile, ScannerType
from src.asset.domain.vulnerabilities import (
    VulnerabilityFinding,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    VulnerabilityStatusHistory,
)
from src.asset.infrastructure.db.models import (
    MonitoringIntegrationModel,
    ScanExecutionModel,
    ScannerProfileModel,
    ScanScheduleModel,
    ScanScheduleTargetModel,
    VulnerabilityFindingModel,
    VulnerabilityHistoryModel,
)


class PostgresScannerProfileRepository:
    """Repositório de Perfis de Scanner."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, profile: ScannerProfile) -> None:
        stmt = select(ScannerProfileModel).where(
            ScannerProfileModel.id == profile.id,
            ScannerProfileModel.tenant_id == profile.tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()

        if m is None:
            m = ScannerProfileModel(
                id=profile.id,
                tenant_id=profile.tenant_id,
                name=profile.name,
                description=profile.description,
                scanner_type=str(profile.scanner_type),
                discovery_enabled=profile.discovery_enabled,
                service_detection_enabled=profile.service_detection_enabled,
                vulnerability_detection_enabled=profile.vulnerability_detection_enabled,
                port_strategy=str(profile.port_strategy),
                custom_ports_json=profile.custom_ports,
                timeout_seconds=profile.timeout_seconds,
                max_parallelism=profile.max_parallelism,
                rate_limit_per_second=profile.rate_limit_per_second,
                active=profile.active,
                created_at=profile.created_at,
                updated_at=profile.updated_at,
                created_by=profile.created_by,
            )
            self._session.add(m)
        else:
            m.name = profile.name
            m.description = profile.description
            m.scanner_type = str(profile.scanner_type)
            m.discovery_enabled = profile.discovery_enabled
            m.service_detection_enabled = profile.service_detection_enabled
            m.vulnerability_detection_enabled = profile.vulnerability_detection_enabled
            m.port_strategy = str(profile.port_strategy)
            m.custom_ports_json = profile.custom_ports
            m.timeout_seconds = profile.timeout_seconds
            m.max_parallelism = profile.max_parallelism
            m.rate_limit_per_second = profile.rate_limit_per_second
            m.active = profile.active
            m.updated_at = profile.updated_at

    async def get_by_id(self, profile_id: UUID, tenant_id: UUID) -> ScannerProfile | None:
        stmt = select(ScannerProfileModel).where(
            ScannerProfileModel.id == profile_id,
            ScannerProfileModel.tenant_id == tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()
        if not m:
            return None
        return ScannerProfile(
            id=m.id,
            tenant_id=m.tenant_id,
            name=m.name,
            description=m.description,
            scanner_type=ScannerType(m.scanner_type),
            discovery_enabled=m.discovery_enabled,
            service_detection_enabled=m.service_detection_enabled,
            vulnerability_detection_enabled=m.vulnerability_detection_enabled,
            port_strategy=PortStrategy(m.port_strategy),
            custom_ports=m.custom_ports_json or [],
            timeout_seconds=m.timeout_seconds,
            max_parallelism=m.max_parallelism,
            rate_limit_per_second=m.rate_limit_per_second,
            active=m.active,
            created_at=m.created_at,
            updated_at=m.updated_at,
            created_by=m.created_by,
        )

    async def list_profiles(
        self, tenant_id: UUID, page: int = 1, page_size: int = 20
    ) -> tuple[list[ScannerProfile], int]:
        stmt = select(ScannerProfileModel).where(ScannerProfileModel.tenant_id == tenant_id)
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_res = await self._session.execute(count_stmt)
        total = total_res.scalar_one() or 0

        stmt = stmt.order_by(ScannerProfileModel.name.asc()).offset((page - 1) * page_size).limit(page_size)
        res = await self._session.execute(stmt)
        rows = list(res.scalars().all())

        profiles = [
            ScannerProfile(
                id=m.id,
                tenant_id=m.tenant_id,
                name=m.name,
                description=m.description,
                scanner_type=ScannerType(m.scanner_type),
                discovery_enabled=m.discovery_enabled,
                service_detection_enabled=m.service_detection_enabled,
                vulnerability_detection_enabled=m.vulnerability_detection_enabled,
                port_strategy=PortStrategy(m.port_strategy),
                custom_ports=m.custom_ports_json or [],
                timeout_seconds=m.timeout_seconds,
                max_parallelism=m.max_parallelism,
                rate_limit_per_second=m.rate_limit_per_second,
                active=m.active,
                created_at=m.created_at,
                updated_at=m.updated_at,
                created_by=m.created_by,
            )
            for m in rows
        ]
        return profiles, total


class PostgresScanScheduleRepository:
    """Repositório de Agendamentos de Scanner."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, schedule: ScanSchedule) -> None:
        stmt = select(ScanScheduleModel).where(
            ScanScheduleModel.id == schedule.id,
            ScanScheduleModel.tenant_id == schedule.tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()

        if m is None:
            m = ScanScheduleModel(
                id=schedule.id,
                tenant_id=schedule.tenant_id,
                name=schedule.name,
                description=schedule.description,
                scanner_profile_id=schedule.scanner_profile_id,
                frequency_type=str(schedule.frequency_type),
                cron_expression=schedule.cron_expression,
                timezone=schedule.timezone,
                start_at=schedule.start_at,
                next_run_at=schedule.next_run_at,
                last_run_at=schedule.last_run_at,
                enabled=schedule.enabled,
                overlap_policy=str(schedule.overlap_policy),
                created_at=schedule.created_at,
                updated_at=schedule.updated_at,
                created_by=schedule.created_by,
                updated_by=schedule.updated_by,
            )
            self._session.add(m)
        else:
            m.name = schedule.name
            m.description = schedule.description
            m.scanner_profile_id = schedule.scanner_profile_id
            m.frequency_type = str(schedule.frequency_type)
            m.cron_expression = schedule.cron_expression
            m.timezone = schedule.timezone
            m.start_at = schedule.start_at
            m.next_run_at = schedule.next_run_at
            m.last_run_at = schedule.last_run_at
            m.enabled = schedule.enabled
            m.overlap_policy = str(schedule.overlap_policy)
            m.updated_at = schedule.updated_at
            m.updated_by = schedule.updated_by

        # Sincronizar ScanScheduleTarget N:N
        await self._session.execute(
            delete(ScanScheduleTargetModel).where(ScanScheduleTargetModel.schedule_id == schedule.id)
        )
        for target_id in schedule.target_ids:
            self._session.add(
                ScanScheduleTargetModel(
                    schedule_id=schedule.id,
                    target_id=target_id,
                    created_at=schedule.updated_at,
                )
            )

    async def get_by_id(self, schedule_id: UUID, tenant_id: UUID) -> ScanSchedule | None:
        stmt = select(ScanScheduleModel).where(
            ScanScheduleModel.id == schedule_id,
            ScanScheduleModel.tenant_id == tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()
        if not m:
            return None

        # Carregar IDs dos alvos vinculados
        t_stmt = select(ScanScheduleTargetModel.target_id).where(
            ScanScheduleTargetModel.schedule_id == schedule_id
        )
        t_res = await self._session.execute(t_stmt)
        target_ids = list(t_res.scalars().all())

        return ScanSchedule(
            id=m.id,
            tenant_id=m.tenant_id,
            name=m.name,
            description=m.description,
            scanner_profile_id=m.scanner_profile_id,
            frequency_type=FrequencyType(m.frequency_type),
            cron_expression=m.cron_expression,
            timezone=m.timezone,
            start_at=m.start_at,
            next_run_at=m.next_run_at,
            last_run_at=m.last_run_at,
            enabled=m.enabled,
            overlap_policy=OverlapPolicy(m.overlap_policy),
            created_at=m.created_at,
            updated_at=m.updated_at,
            created_by=m.created_by,
            updated_by=m.updated_by,
            target_ids=target_ids,
        )

    async def list_schedules(
        self, tenant_id: UUID, page: int = 1, page_size: int = 20
    ) -> tuple[list[ScanSchedule], int]:
        stmt = select(ScanScheduleModel).where(ScanScheduleModel.tenant_id == tenant_id)
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_res = await self._session.execute(count_stmt)
        total = total_res.scalar_one() or 0

        stmt = stmt.order_by(ScanScheduleModel.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        res = await self._session.execute(stmt)
        m_rows = list(res.scalars().all())

        schedules = []
        for m in m_rows:
            t_stmt = select(ScanScheduleTargetModel.target_id).where(
                ScanScheduleTargetModel.schedule_id == m.id
            )
            t_res = await self._session.execute(t_stmt)
            target_ids = list(t_res.scalars().all())

            schedules.append(
                ScanSchedule(
                    id=m.id,
                    tenant_id=m.tenant_id,
                    name=m.name,
                    description=m.description,
                    scanner_profile_id=m.scanner_profile_id,
                    frequency_type=FrequencyType(m.frequency_type),
                    cron_expression=m.cron_expression,
                    timezone=m.timezone,
                    start_at=m.start_at,
                    next_run_at=m.next_run_at,
                    last_run_at=m.last_run_at,
                    enabled=m.enabled,
                    overlap_policy=OverlapPolicy(m.overlap_policy),
                    created_at=m.created_at,
                    updated_at=m.updated_at,
                    created_by=m.created_by,
                    updated_by=m.updated_by,
                    target_ids=target_ids,
                )
            )
        return schedules, total


class PostgresScanExecutionRepository:
    """Repositório de Execuções de Scanner."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, execution: ScanExecution) -> None:
        stmt = select(ScanExecutionModel).where(
            ScanExecutionModel.id == execution.id,
            ScanExecutionModel.tenant_id == execution.tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()

        if m is None:
            m = ScanExecutionModel(
                id=execution.id,
                tenant_id=execution.tenant_id,
                schedule_id=execution.schedule_id,
                scanner_profile_id=execution.scanner_profile_id,
                trigger_type=str(execution.trigger_type),
                status=str(execution.status),
                started_at=execution.started_at,
                finished_at=execution.finished_at,
                requested_by=execution.requested_by,
                targets_total=execution.targets_total,
                targets_processed=execution.targets_processed,
                assets_discovered=execution.assets_discovered,
                services_discovered=execution.services_discovered,
                vulnerabilities_discovered=execution.vulnerabilities_discovered,
                error_summary=execution.error_summary,
                created_at=execution.created_at,
                updated_at=execution.updated_at,
            )
            self._session.add(m)
        else:
            m.status = str(execution.status)
            m.started_at = execution.started_at
            m.finished_at = execution.finished_at
            m.targets_processed = execution.targets_processed
            m.assets_discovered = execution.assets_discovered
            m.services_discovered = execution.services_discovered
            m.vulnerabilities_discovered = execution.vulnerabilities_discovered
            m.error_summary = execution.error_summary
            m.updated_at = execution.updated_at

    async def get_by_id(self, execution_id: UUID, tenant_id: UUID) -> ScanExecution | None:
        stmt = select(ScanExecutionModel).where(
            ScanExecutionModel.id == execution_id,
            ScanExecutionModel.tenant_id == tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()
        if not m:
            return None
        return ScanExecution(
            id=m.id,
            tenant_id=m.tenant_id,
            schedule_id=m.schedule_id,
            scanner_profile_id=m.scanner_profile_id,
            trigger_type=TriggerType(m.trigger_type),
            status=ExecutionStatus(m.status),
            started_at=m.started_at,
            finished_at=m.finished_at,
            requested_by=m.requested_by,
            targets_total=m.targets_total,
            targets_processed=m.targets_processed,
            assets_discovered=m.assets_discovered,
            services_discovered=m.services_discovered,
            vulnerabilities_discovered=m.vulnerabilities_discovered,
            error_summary=m.error_summary,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    async def list_executions(
        self, tenant_id: UUID, status: str | None = None, page: int = 1, page_size: int = 20
    ) -> tuple[list[ScanExecution], int]:
        stmt = select(ScanExecutionModel).where(ScanExecutionModel.tenant_id == tenant_id)
        if status:
            stmt = stmt.where(ScanExecutionModel.status == status)

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_res = await self._session.execute(count_stmt)
        total = total_res.scalar_one() or 0

        stmt = stmt.order_by(ScanExecutionModel.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        res = await self._session.execute(stmt)

        executions = [
            ScanExecution(
                id=m.id,
                tenant_id=m.tenant_id,
                schedule_id=m.schedule_id,
                scanner_profile_id=m.scanner_profile_id,
                trigger_type=TriggerType(m.trigger_type),
                status=ExecutionStatus(m.status),
                started_at=m.started_at,
                finished_at=m.finished_at,
                requested_by=m.requested_by,
                targets_total=m.targets_total,
                targets_processed=m.targets_processed,
                assets_discovered=m.assets_discovered,
                services_discovered=m.services_discovered,
                vulnerabilities_discovered=m.vulnerabilities_discovered,
                error_summary=m.error_summary,
                created_at=m.created_at,
                updated_at=m.updated_at,
            )
            for m in res.scalars()
        ]
        return executions, total


class PostgresVulnerabilityRepository:
    """Repositório de Achados de Vulnerabilidades."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, finding: VulnerabilityFinding) -> None:
        stmt = select(VulnerabilityFindingModel).where(
            VulnerabilityFindingModel.id == finding.id,
            VulnerabilityFindingModel.tenant_id == finding.tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()

        if m is None:
            m = VulnerabilityFindingModel(
                id=finding.id,
                tenant_id=finding.tenant_id,
                asset_id=finding.asset_id,
                asset_service_id=finding.asset_service_id,
                scan_execution_id=finding.scan_execution_id,
                external_id=finding.external_id,
                cve_id=finding.cve_id,
                title=finding.title,
                description=finding.description,
                severity=str(finding.severity),
                cvss_score=finding.cvss_score,
                status=str(finding.status),
                evidence_json=finding.evidence,
                remediation=finding.remediation,
                deduplication_hash=finding.deduplication_hash,
                first_seen_at=finding.first_seen_at,
                last_seen_at=finding.last_seen_at,
                resolved_at=finding.resolved_at,
                created_at=finding.created_at,
                updated_at=finding.updated_at,
            )
            self._session.add(m)
        else:
            m.status = str(finding.status)
            m.severity = str(finding.severity)
            m.cvss_score = float(finding.cvss_score) if finding.cvss_score is not None else None
            m.evidence_json = finding.evidence
            m.remediation = finding.remediation
            m.last_seen_at = finding.last_seen_at
            m.resolved_at = finding.resolved_at
            m.updated_at = finding.updated_at

    async def get_by_id(self, finding_id: UUID, tenant_id: UUID) -> VulnerabilityFinding | None:
        stmt = select(VulnerabilityFindingModel).where(
            VulnerabilityFindingModel.id == finding_id,
            VulnerabilityFindingModel.tenant_id == tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()
        if not m:
            return None
        return VulnerabilityFinding(
            id=m.id,
            tenant_id=m.tenant_id,
            asset_id=m.asset_id,
            asset_service_id=m.asset_service_id,
            scan_execution_id=m.scan_execution_id,
            external_id=m.external_id,
            cve_id=m.cve_id,
            title=m.title,
            description=m.description,
            severity=VulnerabilitySeverity(m.severity),
            cvss_score=Decimal(str(m.cvss_score)) if m.cvss_score is not None else None,
            status=VulnerabilityStatus(m.status),
            evidence=m.evidence_json or {},
            remediation=m.remediation,
            deduplication_hash=m.deduplication_hash,
            first_seen_at=m.first_seen_at,
            last_seen_at=m.last_seen_at,
            resolved_at=m.resolved_at,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    async def list_findings(
        self,
        tenant_id: UUID,
        severity: str | None = None,
        status: str | None = None,
        cve_id: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[VulnerabilityFinding], int]:
        stmt = select(VulnerabilityFindingModel).where(VulnerabilityFindingModel.tenant_id == tenant_id)
        if severity:
            stmt = stmt.where(VulnerabilityFindingModel.severity == severity)
        if status:
            stmt = stmt.where(VulnerabilityFindingModel.status == status)
        if cve_id:
            stmt = stmt.where(VulnerabilityFindingModel.cve_id == cve_id.upper())

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_res = await self._session.execute(count_stmt)
        total = total_res.scalar_one() or 0

        stmt = stmt.order_by(VulnerabilityFindingModel.last_seen_at.desc()).offset((page - 1) * page_size).limit(page_size)
        res = await self._session.execute(stmt)

        findings = [
            VulnerabilityFinding(
                id=m.id,
                tenant_id=m.tenant_id,
                asset_id=m.asset_id,
                asset_service_id=m.asset_service_id,
                scan_execution_id=m.scan_execution_id,
                external_id=m.external_id,
                cve_id=m.cve_id,
                title=m.title,
                description=m.description,
                severity=VulnerabilitySeverity(m.severity),
                cvss_score=Decimal(str(m.cvss_score)) if m.cvss_score is not None else None,
                status=VulnerabilityStatus(m.status),
                evidence=m.evidence_json or {},
                remediation=m.remediation,
                deduplication_hash=m.deduplication_hash,
                first_seen_at=m.first_seen_at,
                last_seen_at=m.last_seen_at,
                resolved_at=m.resolved_at,
                created_at=m.created_at,
                updated_at=m.updated_at,
            )
            for m in res.scalars()
        ]
        return findings, total

    async def save_history(self, history: VulnerabilityStatusHistory) -> None:
        model = VulnerabilityHistoryModel(
            id=history.id,
            tenant_id=history.tenant_id,
            finding_id=history.finding_id,
            from_status=str(history.from_status),
            to_status=str(history.to_status),
            justification=history.justification,
            changed_by=history.changed_by,
            changed_at=history.changed_at,
        )
        self._session.add(model)


class PostgresMonitoringRepository:
    """Repositório de Configurações de Monitoramento Zabbix."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, integration: MonitoringIntegration) -> None:
        stmt = select(MonitoringIntegrationModel).where(
            MonitoringIntegrationModel.id == integration.id,
            MonitoringIntegrationModel.tenant_id == integration.tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()

        if m is None:
            m = MonitoringIntegrationModel(
                id=integration.id,
                tenant_id=integration.tenant_id,
                provider=str(integration.provider),
                name=integration.name,
                base_url=integration.base_url,
                enabled=integration.enabled,
                verify_tls=integration.verify_tls,
                credential_reference=integration.credential_reference,
                last_sync_at=integration.last_sync_at,
                last_sync_status=str(integration.last_sync_status) if integration.last_sync_status else None,
                created_at=integration.created_at,
                updated_at=integration.updated_at,
            )
            self._session.add(m)
        else:
            m.name = integration.name
            m.base_url = integration.base_url
            m.enabled = integration.enabled
            m.verify_tls = integration.verify_tls
            m.credential_reference = integration.credential_reference
            m.last_sync_at = integration.last_sync_at
            m.last_sync_status = str(integration.last_sync_status) if integration.last_sync_status else None
            m.updated_at = integration.updated_at

    async def get_by_id(self, integration_id: UUID, tenant_id: UUID) -> MonitoringIntegration | None:
        stmt = select(MonitoringIntegrationModel).where(
            MonitoringIntegrationModel.id == integration_id,
            MonitoringIntegrationModel.tenant_id == tenant_id,
        )
        res = await self._session.execute(stmt)
        m = res.scalar_one_or_none()
        if not m:
            return None
        return MonitoringIntegration(
            id=m.id,
            tenant_id=m.tenant_id,
            provider=MonitoringProvider(m.provider),
            name=m.name,
            base_url=m.base_url,
            enabled=m.enabled,
            verify_tls=m.verify_tls,
            credential_reference=m.credential_reference,
            last_sync_at=m.last_sync_at,
            last_sync_status=SyncStatus(m.last_sync_status) if m.last_sync_status else None,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )

    async def list_integrations(
        self, tenant_id: UUID, page: int = 1, page_size: int = 20
    ) -> tuple[list[MonitoringIntegration], int]:
        stmt = select(MonitoringIntegrationModel).where(MonitoringIntegrationModel.tenant_id == tenant_id)
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_res = await self._session.execute(count_stmt)
        total = total_res.scalar_one() or 0

        stmt = stmt.order_by(MonitoringIntegrationModel.name.asc()).offset((page - 1) * page_size).limit(page_size)
        res = await self._session.execute(stmt)
        m_rows = list(res.scalars().all())

        integrations = [
            MonitoringIntegration(
                id=m.id,
                tenant_id=m.tenant_id,
                provider=MonitoringProvider(m.provider),
                name=m.name,
                base_url=m.base_url,
                enabled=m.enabled,
                verify_tls=m.verify_tls,
                credential_reference=m.credential_reference,
                last_sync_at=m.last_sync_at,
                last_sync_status=SyncStatus(m.last_sync_status) if m.last_sync_status else None,
                created_at=m.created_at,
                updated_at=m.updated_at,
            )
            for m in m_rows
        ]
        return integrations, total
