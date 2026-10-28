import json
from meta_pipeline.references import ReferenceCatalog

def fixture(tmp_path):
    marker=tmp_path/'must-not-exist'
    p=tmp_path/'catalog.json'
    p.write_text(json.dumps({'shortcuts':{'1':{'id':'ONE','title':'Search file names','command':'touch '+str(marker),'category':'find','use_when':'Find source files','shell':'Bash','risk':'read_only','verification':'safe'},
                                        '2':{'id':'TWO','title':'Malformed shell','command':"echo '",'category':'shell','shell':'Bash','risk':'read_only'}}}))
    return p,marker

def test_reference_import_does_not_grant_permission_or_execute(tmp_path):
    p,marker=fixture(tmp_path);c=ReferenceCatalog(p)
    try:
        report=c.check_syntax()
        assert report['syntax_results']=={'syntax_valid':1,'syntax_invalid':1}
        assert not marker.exists()
        result=c.search('file names')
        assert result[0]['id']=='ONE' and result[0]['execution_permission']=='none'
        assert 'command'not in result[0]
        assert c.summary()['declared_risks']=={'read_only':2}
        assert len(c.summary()['source_sha256'])==64
    finally:c.close()

def test_reference_query_is_literal_and_bounded(tmp_path):
    p,_=fixture(tmp_path);c=ReferenceCatalog(p)
    try:
        assert isinstance(c.search('" OR * DROP TABLE recipes;'),list)
        assert len(c.search('file names'))<=5
        assert c.summary()['entries']==2
    finally:c.close()
