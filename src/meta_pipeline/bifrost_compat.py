"""Narrow HTTPX adapter using Bifrost's documented native extra-params envelope.

It preserves Meta parameters which the installed OpenAI normalizer changes.
It cannot override a model, URL, credential, tool, or unrelated request field.
"""
import copy
import json
import httpx

def preserve_meta_request(data,path):
    if not isinstance(data,dict)or not str(data.get('model','')).startswith('meta/'):
        raise ValueError('Only scoped Meta requests may use this adapter')
    d=copy.deepcopy(data)
    if d.get('extra_params'):
        raise ValueError('Caller-supplied passthrough fields are not permitted')
    extras={}
    if path.rstrip('/').endswith('/chat/completions'):
        if d.get('reasoning_effort')=='minimal':extras['reasoning_effort']='minimal'
    elif path.rstrip('/').endswith('/responses'):
        if (d.get('reasoning')or{}).get('effort')=='minimal':extras['reasoning']={'effort':'minimal'}
        inputs=d.get('input')
        if isinstance(inputs,list)and any(isinstance(i,dict)and i.get('type')=='reasoning'and i.get('encrypted_content')for i in inputs):
            # Restore the SAME already-validated SDK input, not generated override data.
            extras['input']=copy.deepcopy(inputs)
    else:raise ValueError('Unsupported compatibility operation')
    if extras:d['extra_params']=extras
    return d

class BifrostMetaHTTP(httpx.AsyncClient):
    async def send(self,request,**kwargs):
        path=request.url.path.rstrip('/')
        if request.method=='POST'and(path.endswith('/responses')or path.endswith('/chat/completions')):
            data=preserve_meta_request(json.loads(request.content),path)
            content=json.dumps(data,separators=(',',':'),ensure_ascii=False).encode()
            headers={k:v for k,v in request.headers.items()if k.lower()!='content-length'}
            if data.get('extra_params'):headers['x-bf-passthrough-extra-params']='true'
            if path.endswith('/responses'):
                # Tool-loop responses are not application-verified cache entries.
                headers['x-bf-cache-no-store']='true'
            request=httpx.Request(request.method,request.url,headers=headers,content=content,extensions=request.extensions)
        return await super().send(request,**kwargs)
