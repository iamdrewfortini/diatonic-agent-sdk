from pathlib import Path
import pytest
from meta_pipeline.contracts import ChatRequest, ImageRequest, VoiceRequest, VoiceResponse, ResponsesRequest, FileUploadPolicy, text_blocks
from meta_pipeline.models import MODELS, Workload, route
from meta_pipeline.gateway import measured_usage

@pytest.mark.private_reference
def test_supplied_schema_request_fields():
    root=Path(__file__).parents[1]/"vendor/Meta_Schemas/Meta_Schemas"
    if not root.exists():pytest.skip("Private vendor bundle is not installed")
    chat=(root/"Chat_Completions.txt").read_text()
    block=chat.split("Create Chat Completion Request",1)[1].split("Create Chat Completion Response",1)[0]
    for field in ChatRequest.model_fields:
        assert field+"\t" in block
    voice=(root/"Voice_Schemas.txt").read_text()
    block=voice.split("Transcribe Request",1)[1].split("Transcribe Response",1)[0]
    for field in VoiceRequest.model_fields:
        assert field+"\t" in block
    images=(root/"Photo_Schemas.txt").read_text()
    block=images.split("Create Image Request",1)[1].split("Edit Image Body Json Param",1)[0]
    for field in ImageRequest.model_fields:assert field+"\t" in block

def test_voice_schema_duration_and_wrong_openai_shape_rejected():
    response=VoiceResponse(sessionId="test",transcript="ready",audioDurationMs=1999,turns=[])
    amount,detail=measured_usage(response.model_dump(),{},MODELS["muse-voice-transcribe-1.0"])
    assert amount==50000 and detail["audio_seconds"]==1.999
    with pytest.raises(ValueError):VoiceRequest.model_validate({"model":"muse-voice-transcribe-1.0","file":"audio.wav"})
    assert measured_usage({"duration":2},{},MODELS["muse-voice-transcribe-1.0"])[0] is None

def test_schema_boundaries_and_encrypted_reasoning_blocks():
    assert text_blocks([{"type":"redacted_thinking","data":"encrypted"},{"type":"text","text":"answer"}])=="answer"
    with pytest.raises(ValueError):ImageRequest(prompt="x",n=11)
    with pytest.raises(ValueError):FileUploadPolicy(purpose="fine-tune",expires_after={"anchor":"created_at","seconds":3600})
    with pytest.raises(ValueError):FileUploadPolicy(expires_after={"anchor":"created_at","seconds":3599})
    with pytest.raises(ValueError):ResponsesRequest.model_validate({"model":"muse-spark-1.3","input":"x","instructions":"x","max_output_tokens":15,"text":{}})
