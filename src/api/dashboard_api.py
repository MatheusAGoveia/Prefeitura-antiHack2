"""
Endpoint de API para o Dashboard de Desenvolvimento (Leitura da MEMORIA.md e Status do Git)
GovSec Shield — Dev Dashboard API
"""

import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/memoria", tags=["Dev Dashboard"])

MEMORIA_PATH = Path("MEMORIA.md")


class StepItem(BaseModel):
    id: int
    name: str
    status: str  # "done", "in_progress", "pending"
    category: str


class GitInfo(BaseModel):
    branch: str
    last_commit: dict[str, str]
    repo_url: str


class MemoriaDashboardResponse(BaseModel):
    memoria: str
    last_update: str
    total_steps: int
    completed_steps: int
    progress_percentage: float
    steps: list[StepItem]
    git: GitInfo


def _get_git_info() -> GitInfo:
    branch = os.getenv("GOVSEC_GIT_BRANCH", "main")
    commit_hash = os.getenv("GOVSEC_GIT_COMMIT", "a1b2c3d")
    commit_msg = os.getenv("GOVSEC_GIT_MSG", "GovSec Shield Release")
    commit_author = os.getenv("GOVSEC_GIT_AUTHOR", "GovSec Shield Core Team")
    commit_date = os.getenv("GOVSEC_GIT_DATE", datetime.now(timezone.utc).isoformat())

    return GitInfo(
        branch=branch,
        last_commit={
            "hash": commit_hash,
            "message": commit_msg,
            "author": commit_author,
            "date": commit_date,
        },
        repo_url="https://github.com/MatheusAGoveia/Prefeitura-antiHack2",
    )


def _parse_memoria_content(content: str) -> tuple[list[StepItem], str]:
    steps: list[StepItem] = []
    lines = content.splitlines()
    step_id = 1
    current_category = "Geral"

    last_update = datetime.now(timezone.utc).isoformat()
    for line in lines:
        if "Data da Última Atualização:" in line or "Data de Execução:" in line:
            match = re.search(r"\d{4}-\d{2}-\d{2}T?\d{2}:\d{2}:\d{2}Z?", line)
            if match:
                last_update = match.group(0)

        if line.startswith("### "):
            current_category = line.replace("### ", "").strip()
        elif line.startswith("## ") and not line.startswith("## 📌"):
            current_category = line.replace("## ", "").strip()

        # Parse checkboxes: - [x] or - [ ]
        if re.match(r"^\s*-\s*\[[ xX]\]", line):
            is_done = bool(re.match(r"^\s*-\s*\[[xX]\]", line))
            # Clean text
            text = re.sub(r"^\s*-\s*\[[ xX]\]\s*", "", line).strip()
            # Clean Markdown links / formatting for short name
            clean_name = re.sub(r"\[(.*?)\]\(.*?\)", r"\1", text)

            status = "done" if is_done else "pending"
            steps.append(
                StepItem(id=step_id, name=clean_name, status=status, category=current_category)
            )
            step_id += 1

    return steps, last_update


@router.get("", response_model=MemoriaDashboardResponse)
async def get_memoria_dashboard() -> MemoriaDashboardResponse:
    if not MEMORIA_PATH.exists():
        raise HTTPException(status_code=404, detail="Arquivo MEMORIA.md não encontrado")

    content = MEMORIA_PATH.read_text(encoding="utf-8")
    steps, last_update = _parse_memoria_content(content)

    total = len(steps)
    completed = sum(1 for s in steps if s.status == "done")
    percentage = round((completed / total * 100), 1) if total > 0 else 0.0

    git_info = _get_git_info()

    return MemoriaDashboardResponse(
        memoria=content,
        last_update=last_update,
        total_steps=total,
        completed_steps=completed,
        progress_percentage=percentage,
        steps=steps,
        git=git_info,
    )
