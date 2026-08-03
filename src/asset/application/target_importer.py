"""
Utilitário de Importação em Massa e Validação de Alvos (CSV, XLSX, PDF textual, TXT, Raw Paste).
GovSec Shield — Application Layer (M3.4)
"""

import csv
import io
import re
import xml.etree.ElementTree as ET
import zipfile
from typing import Any

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

# Tabela de compatibilidade estrita de extensões e tipos MIME
ALLOWED_MIME_TYPES = {
    "csv": {
        "text/csv",
        "text/plain",
        "application/csv",
        "application/vnd.ms-excel",
        "text/x-csv",
        "application/x-csv",
    },
    "txt": {"text/plain", "text/csv"},
    "xlsx": {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/zip",
        "application/x-zip-compressed",
    },
    "pdf": {"application/pdf"},
}


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
        content_type: str | None = None,
        raw_paste: str | None = None,
        items_list: list[str] | None = None,
    ) -> list[str]:
        """Extrai linhas de texto bruto das diversas fontes fornecidas com validação de MIME, extensão e magic bytes."""
        if content is not None:
            if len(content) == 0:
                raise AssetDomainError("O arquivo fornecido está vazio.")

            if len(content) > MAX_FILE_SIZE_BYTES:
                raise AssetDomainError(
                    f"O tamanho do arquivo excede o limite máximo de 5MB ({len(content)} bytes)."
                )

            # Rejeição de executáveis conhecidos por assinatura magic bytes (MZ para Windows PE, \x7fELF para Linux)
            if content.startswith(b"MZ") or content.startswith(b"\x7fELF"):
                raise AssetDomainError("Arquivos executáveis não são permitidos por razões de segurança.")

            ext = (filename or "").split(".")[-1].lower() if filename and "." in filename else ""

            if ext == "xls":
                raise AssetDomainError(
                    "O formato de arquivo '.xls' (legado) não é suportado. Por favor utilize '.xlsx', '.csv' ou '.txt'."
                )

            if ext not in ALLOWED_MIME_TYPES:
                raise AssetDomainError(
                    f"Formato de arquivo '.{ext}' não suportado. Os formatos aceitos são: .csv, .txt, .xlsx e .pdf."
                )

            # Validação do tipo MIME do cabeçalho de upload (caso fornecido)
            if content_type:
                clean_mime = content_type.split(";")[0].strip().lower()
                allowed_for_ext = ALLOWED_MIME_TYPES[ext]
                if clean_mime not in allowed_for_ext:
                    raise AssetDomainError(
                        f"Tipo MIME '{content_type}' incompatível com a extensão '.{ext}' do arquivo."
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
                if content.startswith(b"PK\x03\x04") or content.startswith(b"%PDF-"):
                    raise AssetDomainError("Assinatura de arquivo binário detectada em arquivo de texto. Formato inválido.")
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
        dialect = ";" if ";" in text[:500] else ","
        reader = csv.reader(io.StringIO(text), delimiter=dialect)
        for row in reader:
            for cell in row:
                cell_clean = cell.strip()
                if cell_clean:
                    lines.append(cell_clean)
        return lines

    @classmethod
    def _parse_xlsx_bytes(cls, content: bytes) -> list[str]:
        """Parse seguro de planilhas XLSX utilizando zipfile + ElementTree com bloqueio de fórmulas e macros."""
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                namelist = zf.namelist()

                # Rejeição imediata de arquivos com macros ou links externos
                for name in namelist:
                    name_lower = name.lower()
                    if "vbaproject.bin" in name_lower or "externallinks/" in name_lower:
                        raise AssetDomainError("Macros e links externos não são permitidos em planilhas XLSX.")

                # Ler sharedStrings.xml se existir
                shared_strings: list[str] = []
                if "xl/sharedStrings.xml" in namelist:
                    ss_xml = zf.read("xl/sharedStrings.xml")
                    tree = ET.fromstring(ss_xml)
                    for si in tree.findall("{*}si"):
                        # Extrai texto de <t> direto ou de run <r><t>
                        texts: list[str] = []
                        for t in si.findall(".//{*}t"):
                            if t.text:
                                texts.append(t.text)
                        full_str = "".join(texts).strip()
                        shared_strings.append(full_str)

                # Identificar a primeira planilha de dados
                sheet_name = None
                for name in namelist:
                    if name.startswith("xl/worksheets/sheet") and name.endswith(".xml"):
                        sheet_name = name
                        break

                if not sheet_name:
                    raise AssetDomainError("Planilha XLSX vazia ou sem planilhas válidas.")

                sheet_xml = zf.read(sheet_name)
                tree = ET.fromstring(sheet_xml)

                lines: list[str] = []

                # Iterar pelas células <c> da planilha
                for c in tree.findall(".//{*}c"):
                    # Rejeitar células contendo fórmulas explícitas <f>
                    if c.find("{*}f") is not None:
                        raise AssetDomainError("Planilhas contendo fórmulas não são permitidas por razões de segurança.")

                    t_attr = c.attrib.get("t")
                    v_elem = c.find("{*}v")

                    if t_attr == "s":
                        # Célula de Shared String
                        if v_elem is not None and v_elem.text:
                            v_text = v_elem.text.strip()
                            if v_text.isdigit():
                                idx = int(v_text)
                                if 0 <= idx < len(shared_strings):
                                    cell_val = shared_strings[idx]
                                    if cell_val:
                                        lines.append(cell_val)
                    elif t_attr == "inlineStr":
                        # Célula Inline String <is><t>
                        is_elem = c.find("{*}is")
                        if is_elem is not None:
                            t_elem = is_elem.find(".//{*}t")
                            if t_elem is not None and t_elem.text:
                                cell_val = t_elem.text.strip()
                                if cell_val:
                                    lines.append(cell_val)
                    else:
                        # Célula Numérica ou Direta
                        if v_elem is not None and v_elem.text:
                            cell_val = v_elem.text.strip()
                            if cell_val:
                                lines.append(cell_val)

                    if len(lines) > MAX_IMPORT_RECORDS * 5:
                        break

                return lines

        except zipfile.BadZipFile as err:
            raise AssetDomainError("Arquivo XLSX corrompido ou inválido.") from err
        except AssetDomainError:
            raise
        except Exception as err:
            raise AssetDomainError(f"Erro ao processar arquivo XLSX: {err}") from err

    @classmethod
    def _parse_pdf_bytes(cls, content: bytes) -> list[str]:
        """Extrai texto de PDFs textuais utilizando inspeção de streams PDF nativos sem OCR."""
        if not content.startswith(b"%PDF-"):
            raise AssetDomainError("Arquivo PDF inválido ou cabeçalho PDF corrompido.")

        text_content = ""
        pattern_tj = re.compile(b"\\((.*?)\\)\\s*Tj", re.DOTALL)
        matches = pattern_tj.findall(content)
        if matches:
            text_content = " ".join(m.decode("latin-1", errors="ignore") for m in matches)
        else:
            text_blocks = re.findall(b"BT(.*?)ET", content, re.DOTALL)
            if text_blocks:
                text_content = " ".join(b.decode("latin-1", errors="ignore") for b in text_blocks)

        if not text_content or not text_content.strip():
            raise AssetDomainError("PDF não possui camada de texto extraível. OCR ainda não é suportado.")

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

            # Checagem de Fórmula / Executável
            if EXEC_FORMULA_REGEX.match(original):
                errors.append("Injeção de fórmula ou conteúdo executável detectado.")

            # Tenta inferir tipo e validar alvo
            target_type = "single_ip"
            if "/" in original and not original.startswith("http"):
                target_type = "cidr"
            elif "-" in original and not original.startswith("http"):
                target_type = "ip_range"
            elif any(c.isalpha() for c in original) and "." in original:
                target_type = "hostname"

            norm_val: str | None = None
            if not errors:
                val_res = IPTargetValidator.validate_and_normalize(
                    target_type=target_type,
                    target_value=original,
                    allow_public_targets=allow_public_targets,
                )
                if not val_res.is_valid:
                    errors.append(val_res.error_message or "Alvo de scanner inválido.")
                else:
                    norm_val = val_res.normalized_value
                    if val_res.security_warnings:
                        warnings.extend(val_res.security_warnings)

            is_duplicate = False
            if norm_val:
                if norm_val in existing_target_values or norm_val in seen_in_file:
                    is_duplicate = True
                    duplicate_count += 1
                    warnings.append(f"Alvo duplicado '{norm_val}' já cadastrado ou presente no mesmo lote.")
                else:
                    seen_in_file.add(norm_val)

            is_valid = len(errors) == 0 and not is_duplicate
            if is_valid:
                valid_count += 1
            else:
                invalid_count += 1

            items.append(
                TargetImportPreviewItemDTO(
                    line_number=idx,
                    original_text=original,
                    target_type=target_type,
                    normalized_value=norm_val or original,
                    valid=is_valid,
                    duplicate=is_duplicate,
                    errors=errors,
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
