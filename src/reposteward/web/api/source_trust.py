"""明确的用户级授权动作，普通导入请求不能携带信任配置。"""

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from reposteward.projects.registry import ProjectError
from reposteward.tasks.local_operations import OperationError
from reposteward.web.api.operations import Key, ProjectID, envelope
from reposteward.web.api.schemas import Record, Response


class CandidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    import_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    target: str = Field(default="", max_length=4096)
    paths: list[str] = Field(min_length=1, max_length=100)


class TrustSaveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    import_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    check_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    expected_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    paths: list[str] = Field(min_length=1, max_length=100)


def routes(service, *, manage_local):
    router = APIRouter(prefix="/api/v1")

    def invoke(method, **kwargs):
        if service is None or not manage_local:
            raise OperationError("read_only", "当前会话仅允许读取。", 403)
        try:
            return envelope(getattr(service.source_trust, method)(**kwargs))
        except (ValueError, RuntimeError, OSError) as exc:
            message = str(exc) if isinstance(exc, ProjectError) else "候选或配置不可用；请核对配置并重新检查，保存结果可查询或重试确认。"
            raise OperationError("source_trust", message, 409) from exc

    @router.post("/commands/source-trust/check", response_model=Response[Record], operation_id="checkSourceTrust")
    def check(request: CandidateRequest, key: Key):
        return invoke("check", **request.model_dump(), key=key)

    @router.post("/commands/source-trust/save", response_model=Response[Record], operation_id="saveSourceTrust")
    def save(request: TrustSaveRequest, key: Key):
        return invoke("save", **request.model_dump(), key=key)

    @router.get("/source-trust-result", response_model=Response[Record], operation_id="sourceTrustResult")
    def status(request_id: ProjectID):
        return invoke("status", request_id=request_id)

    return router
