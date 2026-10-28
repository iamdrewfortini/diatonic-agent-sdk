"""Audited request subsets from the Owner10 Meta_Schemas.7z reference bundle.

These typed subsets cover this application's operations; they do not claim to
reproduce every optional field in the nine vendor reference documents.
"""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class Contract(BaseModel):
    model_config=ConfigDict(extra="forbid",strict=True)

class TextMessage(Contract):
    role: Literal["developer","system","user"]
    content: str

class JsonSchemaBody(Contract):
    name: str
    strict: Literal[True] = True
    schema_: dict = Field(alias="schema")

class JsonFormat(Contract):
    type: Literal["json_schema"] = "json_schema"
    json_schema: JsonSchemaBody

class ChatRequest(Contract):
    # Provider-prefix routing is stripped before validating the Meta body.
    model: str
    messages: list[TextMessage] = Field(min_length=1,max_length=16)
    max_completion_tokens: int = Field(ge=1,le=16384)
    response_format: JsonFormat
    temperature: float = Field(default=0,ge=0,le=2)
    reasoning_effort: Literal["minimal"] = "minimal"
    store: Literal[False] = False
    stream: Literal[False] = False

class ResponsesFormat(Contract):
    type: Literal["json_schema"] = "json_schema"
    name: str
    strict: Literal[True] = True
    schema_: dict = Field(alias="schema")

class ResponsesText(Contract):
    format: ResponsesFormat

class ResponsesRequest(Contract):
    model: str
    input: str
    instructions: str
    max_output_tokens: int = Field(ge=16,le=16384)
    text: ResponsesText
    store: Literal[False] = False
    background: Literal[False] = False
    stream: Literal[False] = False

class ImageRequest(Contract):
    model: Literal["muse-image-1.0"] = "muse-image-1.0"
    prompt: str
    n: int = Field(default=1,ge=1,le=10)
    response_format: Literal["url","b64_json"] = "b64_json"
    output_format: Literal["png","jpeg","webp"] = "webp"
    reasoning_strength: Literal["low","high"] = "low"

class VoiceRequest(Contract):
    # JSON 'request' part, PLUS binary 'audio' part: NOT OpenAI's model/file body.
    model: Literal["muse-voice-transcribe-1.0"] = "muse-voice-transcribe-1.0"
    audioEncoding: Literal["WAV"] = "WAV"
    mode: Literal["PUSH_TO_TALK","ENDPOINTING","DIARIZATION"] = "PUSH_TO_TALK"
    keywords: list[str] = Field(default_factory=list,max_length=100)
    languageBias: list[str] = Field(default_factory=list,max_length=25)

class VoiceResponse(Contract):
    sessionId: str
    transcript: str
    audioDurationMs: int = Field(ge=0)
    turns: list[dict]

class FileExpiration(Contract):
    anchor: Literal["created_at"] = "created_at"
    seconds: int = Field(ge=3600,le=2592000)

class FileUploadPolicy(Contract):
    purpose: Literal["user_data","batch"] = "user_data"
    expires_after: FileExpiration

class ModelObject(BaseModel):
    model_config=ConfigDict(extra="allow")
    id: str
    object: Literal["model"] = "model"
    created: int
    owned_by: str

def text_blocks(content):
    """Messages API starts with encrypted/redacted reasoning; don't index [0]."""
    return "".join(b["text"] for b in content if b.get("type")=="text" and isinstance(b.get("text"),str))

def chat_contract(model,messages,maximum,schema):
    return ChatRequest.model_validate({"model":model,"messages":messages,"max_completion_tokens":maximum,
        "temperature":0,"response_format":{"type":"json_schema","json_schema":{"name":"validation","strict":True,"schema":schema}}})
