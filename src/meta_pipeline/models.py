"""Capability and billing registry. Prices verified against Meta 2026-10-28.

Rates are nano-USD per unit (integer arithmetic), not gateway invoice claims.
"""
from dataclasses import dataclass, asdict
from math import ceil, floor
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

PRICE_SOURCE = "https://dev.meta.ai/docs/pricing-rate-limits"
PRICE_DATE = "2026-10-28"

@dataclass(frozen=True)
class Model:
    id: str
    output: str
    endpoints: tuple[str, ...]
    inputs: tuple[str, ...]
    input_nusd: int = 0
    cached_nusd: int = 0
    output_nusd: int = 0
    contributor: bool = False
    hosted: bool = True
    context: int | None = 1048576
    audio_recommended: bool = True
    billing: str = "tokens"
    rpm: int | None = 3000
    tpm: int | None = 4000000

TEXT_ENDPOINTS = ("responses", "chat", "messages")
MULTIMODAL = ("text", "image", "video", "audio", "pdf")
MODELS: dict[str, Model] = {}
for version in ("1.3", "1.2", "1.1"):
    mid = f"muse-spark-{version}"
    MODELS[mid] = Model(mid, "text", TEXT_ENDPOINTS, MULTIMODAL,
                        1250, 150, 4250, audio_recommended=version != "1.3")
    if version != "1.1":
        cid = mid + "-contributor"
        MODELS[cid] = Model(cid, "text", TEXT_ENDPOINTS, MULTIMODAL,
                            100, 2, 200, contributor=True,
                            audio_recommended=version != "1.3", rpm=150, tpm=3000000)
MODELS["muse-wonder-1.0"] = Model("muse-wonder-1.0", "text", TEXT_ENDPOINTS,
                                  MULTIMODAL, 4000, 200, 20000)
MODELS["muse-image-1.0"] = Model("muse-image-1.0", "image", ("responses", "images"),
                                ("text", "image"), context=None, billing="images", rpm=150, tpm=None)
MODELS["muse-voice-transcribe-1.0"] = Model("muse-voice-transcribe-1.0", "transcript",
    ("transcribe", "asr_realtime"), ("audio",), context=None, billing="audio_seconds", rpm=None, tpm=None)
MODELS["sam-3.1"] = Model("sam-3.1", "geometry", ("responses", "segmentation"),
    ("text", "image", "video"), context=None, billing="segmentation", tpm=None)
# Family identifiers only: never manufacture an API model ID for open weights.
for family in ("Muse Spark Open", "Muse Glimmer"):
    MODELS[family] = Model(family, "text", (), ("text", "image", "video", "audio") if family=="Muse Spark Open" else ("text", "image"),
        hosted=False, context=None, billing="self_hosted_unpriced", rpm=None, tpm=None)

class Workload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    task: Literal["classify", "plan", "audio_understanding", "transcribe", "generate_image", "segment"] = "classify"
    input_kind: Literal["text", "image", "audio", "video", "pdf"] = "text"
    model: str | None = None
    allow_contributor: bool = False
    input_tokens: int = Field(default=0, ge=0)
    cached_tokens: int = Field(default=0, ge=0)
    max_output_tokens: int = Field(default=512, ge=1, le=16384)
    images: int = Field(default=0, ge=0)
    audio_seconds: float = Field(default=0, ge=0, allow_inf_nan=False)
    # Per-request frame counts: SAM's minimum applies to EACH video request.
    video_frames: list[int] = Field(default_factory=list, max_length=1000)
    search_queries: int = Field(default=0, ge=0)
    source_bytes: int = Field(default=0, ge=0)
    network_bytes: int = Field(default=0, ge=0)
    hdd_read_bytes: int = Field(default=0, ge=0)
    hdd_write_bytes: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def check(self):
        if self.cached_tokens > self.input_tokens or any(f <= 0 for f in self.video_frames):
            raise ValueError("invalid cached token or video frame count")
        return self

def route(w: Workload) -> Model:
    default = {"classify": "muse-spark-1.3", "plan": "muse-wonder-1.0",
        "audio_understanding": "muse-spark-1.2", "transcribe": "muse-voice-transcribe-1.0",
        "generate_image": "muse-image-1.0", "segment": "sam-3.1"}[w.task]
    if w.task=="classify" and w.input_kind=="audio":default="muse-spark-1.2"
    if w.allow_contributor and w.task in ("classify", "audio_understanding"):
        default += "-contributor"
    m = MODELS[w.model or default]
    if not m.hosted:
        raise ValueError("Self-hosted family requires a verified serving endpoint; no Meta API route")
    if m.contributor and not w.allow_contributor:
        raise ValueError("Contributor mode requires explicit data-training opt-in")
    expected = {"transcribe": "transcript", "generate_image": "image", "segment": "geometry"}.get(w.task, "text")
    if m.output != expected or w.input_kind not in m.inputs:
        raise ValueError("Model cannot produce requested output from the requested input")
    if w.task == "audio_understanding" and (w.input_kind != "audio" or not m.audio_recommended):
        raise ValueError("Use Spark 1.2 or Wonder for audio understanding")
    if w.task == "transcribe" and w.input_kind != "audio":
        raise ValueError("Transcription requires audio input")
    if w.task == "segment" and w.input_kind not in ("image", "video"):
        raise ValueError("Segmentation requires image or video input")
    if m.context and w.input_tokens + w.max_output_tokens > m.context:
        raise ValueError("Context budget exceeded")
    return m

def bill_nusd(m: Model, *, input_tokens=0, cached_tokens=0, output_tokens=0,
              images=0, audio_seconds=0, video_frames=(), search_queries=0) -> int:
    if min(input_tokens, cached_tokens, output_tokens, images, audio_seconds, search_queries) < 0 or cached_tokens > input_tokens:
        raise ValueError("Invalid usage")
    if any(f <= 0 for f in video_frames):
        raise ValueError("Invalid video frame usage")
    if m.billing == "tokens":
        return ((input_tokens-cached_tokens)*m.input_nusd + cached_tokens*m.cached_nusd
                + output_tokens*m.output_nusd + search_queries*2500000)
    if m.billing == "images":
        return images*10000000
    if m.billing == "audio_seconds":
        return floor(audio_seconds)*50000
    if m.billing == "segmentation":
        return images*2500000 + sum(max(50, f) for f in video_frames)*200000
    raise ValueError("Unknown self-hosted operating cost")

def forecast(w: Workload) -> dict:
    m = route(w)
    units = dict(input_tokens=w.input_tokens, cached_tokens=w.cached_tokens,
        output_tokens=w.max_output_tokens, images=w.images,
        audio_seconds=ceil(w.audio_seconds), video_frames=w.video_frames, search_queries=w.search_queries)
    # Don't assume a prefix-cache hit when reserving spend.
    reserve = bill_nusd(m, **{**units, "cached_tokens": 0})
    if m.billing == "images" and not w.images:
        raise ValueError("Number of images is required")
    if m.billing == "audio_seconds" and not w.audio_seconds:
        raise ValueError("Audio duration is required")
    if m.billing == "segmentation" and not (w.images or w.video_frames):
        raise ValueError("Image count or per-request video frame counts are required")
    return {"model": m.id, "output": m.output, "billing_unit": m.billing,
        "projected_nusd": bill_nusd(m, **units), "reserve_nusd": reserve,
        "pricing_date": PRICE_DATE, "pricing_source": PRICE_SOURCE,
        "token_basis": "caller estimate; no exact Meta tokenizer assumed",
        "units": units, "source_bytes": w.source_bytes, "network_bytes": w.network_bytes,
        "hdd_read_bytes": w.hdd_read_bytes, "hdd_write_bytes": w.hdd_write_bytes,
        "hdd_read_min_seconds": w.hdd_read_bytes/100000000,
        "hdd_write_min_seconds": w.hdd_write_bytes/100000000,
        "time_basis": "ideal lower bounds at separate device caps; no measured job duration",
        "gateway_cache_hit_assumed": False}

def catalog() -> list[dict]:
    return [asdict(m) for m in MODELS.values()]
