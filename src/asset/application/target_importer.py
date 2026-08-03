"""
Utilitário de Importação em Massa e Validação de Alvos (CSV, XLSX, PDF textual, TXT, Raw Paste).
GovSec Shield — Application Layer (M3.4)
"""

import csv
import io
import re
import zipfile
from xml.etree import ElementTree as etree  # noqa: N813 # nosec B405

from src.asset.application.dto import (
    TargetImportPreviewItemDTO,
    TargetImportPreviewResponseDTO,
)
from src.asset.domain.exceptions import AssetDomainError
from src.asset.domain.scan_targets import IPTargetValidator

# Padrão para bloqueio de injeção de fórmulas e conteúdos executáveis
EXEC_FORMULA_REGEX = re.compile(
    r"^\s*([=+\-@]|cmd\||powershell|<script|javascript:)", re.IGNORECASE
)

MAX_IMPORT_RECORDS = 1000
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB


class TargetBulkImporter:
    """
    Parser e validador de importação em massa de alvos de scanner.
    Suporta CSV, XLSX, PDF (textual), TXT e Colagem de Lista (raw_paste).
    """

    @classmethod
    def parse_raw_content(
        cls,
        filename: str | None,
        content: bytes | None,
        raw_paste: str | None = None,
        items_list: list[str] | None = None,
    ) -> list[str]:
        """Extrai linhas de texto bruto das diversas fontes fornecidas."""
        if content is not None:
            if len(content) > MAX_FILE_SIZE_BYTES:
                raise AssetDomainError(
                    f"O tamanho do arquivo excede o limite máximo de 5MB ({len(content)} bytes)."
                )

            ext = (filename or "").split(".")[-1].lower() if filename and "." in filename else ""

            if ext == "xls":
                raise AssetDomainError(
                    "O formato de arquivo '.xls' (legado) não é suportado. Por favor utilize '.xlsx', '.csv' ou '.txt'."
                )

            if ext not in ("csv", "txt", "xlsx", "pdf"):
                raise AssetDomainError(
                    f"Formato de arquivo '.{ext}' não suportado. Os formatos aceitos são: .csv, .txt, .xlsx e .pdf."
                )

            if ext == "xlsx":
                if not content.startswith(b"PK\x03\x04"):
                    raise AssetDomainError("Assinatura de arquivo XLSX inválida ou arquivo corrompido.")
                return cls._parse_xlsx_bytes(content)
            elif ext == "pdf":
                if not content.startswith(b"%PDF-"):
                    raise AssetDomainError("Assinatura de arquivo PDF inválida ou arquivo corrompido.")
                return cls._parse_pdf_bytes(content)
            elif ext in ("csv", "txt"):
                return cls._parse_text_bytes(content)

        if raw_paste:
            return [line.strip() for line in raw_paste.splitlines() if line.strip()]

        if items_list:
            return [str(item).strip() for item in items_list if str(item).strip()]

        raise AssetDomainError("Nenhum arquivo ou lista de alvos foi fornecida.")

    @classmethod
    def _parse_text_bytes(cls, content: bytes) -> list[str]:
        """Parse de arquivos CSV ou TXT."""
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                text = content.decode("latin-1")
            except UnicodeDecodeError as err:
                raise AssetDomainError("Codificação do arquivo inválida. Utilize UTF-8.") from err

        lines: list[str] = []
        # Utiliza csv.reader para suportar CSVs delimitados por vírgula ou ponto-e-vírgula
        dialect = "," if ";" not in text[:500] else ";"
        reader = csv.reader(io.StringIO(text), delimiter=dialect)
        for row in reader:
            for cell in row:
                cell_clean = cell.strip()
                if cell_clean:
                    lines.append(cell_clean)
        return lines

    @classmethod
    def _parse_xlsx_bytes(cls, content: bytes) -> list[str]:
        """Parse seguro de planilhas XLSX utilizando zipfile + ElementTree (stdlib)."""
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                # Ler sharedStrings.xml se existir
                shared_strings: list[str] = []
                if "xl/sharedStrings.xml" in zf.namelist():
                    ss_xml = zf.read("xl/sharedStrings.xml")
                    tree = etree.fromstring(ss_xml)  # nosec B314
                    for elem in tree.iter():
                        if elem.tag.endswith("t") and elem.text:
                            shared_strings.append(elem.text.strip())

                # Ler sheet1.xml
                sheet_name = None
                for name in zf.namelist():
                    if name.startswith("xl/worksheets/sheet") and name.endswith(".xml"):
                        sheet_name = name
                        break

                if not sheet_name:
                    raise AssetDomainError("Planilha XLSX vazia ou sem planilhas válidas.")

                sheet_xml = zf.read(sheet_name)
                tree = etree.fromstring(sheet_xml)  # nosec B314

                lines: list[str] = []
                for elem in tree.iter():
                    if elem.tag.endswith("v") and elem.text:
                        val = elem.text.strip()
                        if val.isdigit() and int(val) < len(shared_strings):
                            lines.append(shared_strings[int(val)])
                        else:
                            lines.append(val)
                return lines
        except zipfile.BadZipFile as err:
            raise AssetDomainError("Arquivo XLSX corrompido ou inválido.") from err
        except AssetDomainError:
            raise
        except Exception as err:
            raise AssetDomainError(f"Erro ao processar arquivo XLSX: {err}") from err

    @classmethod
    def _parse_pdf_bytes(cls, content: bytes) -> list[str]:
        """Extrai texto de PDFs textuais utilizando inspeção de streams PDF nativos."""
        if not content.startswith(b"%PDF-"):
            raise AssetDomainError("Arquivo PDF inválido ou cabeçalho PDF corrompido.")

        # Busca por alvos em streams de texto do PDF (padrões Tj, TJ ou texto simples)
        text_content = ""
        # Decodificação segura de blocos de texto PDF
        pattern_tj = re.compile(b"\\((.*?)\\)\\s*Tj", re.DOTALL)
        matches = pattern_tj.findall(content)
        if matches:
            text_content = " ".join(m.decode("latin-1", errors="ignore") for m in matches)
        else:
            # Tenta encontrar blocos textuais genéricos
            text_blocks = re.findall(b"BT(.*?)ET", content, re.DOTALL)
            if text_blocks:
                text_content = " ".join(b.decode("latin-1", errors="ignore") for b in text_blocks)

        if not text_content or not text_content.strip():
            raise AssetDomainError("PDF não possui camada de texto extraível. OCR ainda não é suportado.")

        # Extrai linhas ou tokens de texto
        tokens = re.split(r"[\s,\n\r;]+", text_content)
        clean_tokens = [t.strip() for t in tokens if t.strip() and not t.startswith("/")]
        if not clean_tokens:
            raise AssetDomainError("PDF não possui camada de texto extraível. OCR ainda não é suportado.")
        return clean_tokens

    @classmethod
    def generate_preview(
        cls,
        raw_lines: list[str],
        existing_target_values: set[str],
        allow_public_targets: bool = False,
    ) -> TargetImportPreviewResponseDTO:
        """Gera preview detalhado sem persistir dados no banco."""
        if len(raw_lines) > MAX_IMPORT_RECORDS:
            raise AssetDomainError(
                f"A quantidade de registros ({len(raw_lines)}) excede o limite máximo permitido de {MAX_IMPORT_RECORDS} alvos."
            )

        items: list[TargetImportPreviewItemDTO] = []
        seen_in_file: set[str] = set()

        valid_count = 0
        invalid_count = 0
        duplicate_count = 0

        for idx, line in enumerate(raw_lines, start=1):
            original = line.strip()
            errors: list[str] = []
            warnings: list[str] = []

            # 1. Checagem de Fórmula / Executável
            if EXEC_FORMULA_REGEX.match(original):
                errors.append(
                    "Conteúdo rejeitado por conter formato de fórmula ou instrução executável não permitida."
                )

            if errors:
                invalid_count += 1
                items.append(
                    TargetImportPreviewItemDTO(
                        line=idx,
                        original_value=original,
                        normalized_value=original,
                        target_type="invalid",
                        valid=False,
                        errors=errors,
                        estimated_addresses=0,
                        warnings=[],
                    )
                )
                continue

            # 2. Validação de Domínio via IPTargetValidator
            res = IPTargetValidator.validate_target(original, allow_public_targets=allow_public_targets)
            if not res.is_valid:
                errors.append(res.error_message or "Endereço ou formato de alvo inválido.")
                invalid_count += 1
                items.append(
                    TargetImportPreviewItemDTO(
                        line=idx,
                        original_value=original,
                        normalized_value=original,
                        target_type="invalid",
                        valid=False,
                        errors=errors,
                        estimated_addresses=0,
                        warnings=[],
                    )
                )
                continue

            normalized = res.normalized_value or original
            target_type = res.target_type or "unknown"
            est_addr = res.estimated_addresses

            # 3. Avisos para faixas grandes
            if est_addr > 256:
                warnings.append(
                    f"Alvo compreende uma faixa ampla com cerca de {est_addr} endereços IP."
                )
            if res.security_warnings:
                warnings.extend(res.security_warnings)

            # 4. Checagem de Duplicidade
            is_dup = False
            if normalized in seen_in_file:
                errors.append("Alvo duplicado dentro do próprio arquivo/lista.")
                is_dup = True
            elif normalized in existing_target_values:
                errors.append("Alvo já cadastrado no grupo de ativos deste tenant.")
                is_dup = True

            if is_dup:
                duplicate_count += 1
                items.append(
                    TargetImportPreviewItemDTO(
                        line=idx,
                        original_value=original,
                        normalized_value=normalized,
                        target_type=target_type,
                        valid=False,
                        errors=errors,
                        estimated_addresses=est_addr,
                        warnings=warnings,
                    )
                )
            else:
                seen_in_file.add(normalized)
                valid_count += 1
                items.append(
                    TargetImportPreviewItemDTO(
                        line=idx,
                        original_value=original,
                        normalized_value=normalized,
                        target_type=target_type,
                        valid=True,
                        errors=[],
                        estimated_addresses=est_addr,
                        warnings=warnings,
                    )
                )

        return TargetImportPreviewResponseDTO(
            total_received=len(raw_lines),
            valid=valid_count,
            invalid=invalid_count,
            duplicates=duplicate_count,
            items=items,
        )
