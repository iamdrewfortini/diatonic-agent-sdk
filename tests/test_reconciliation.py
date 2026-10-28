import pytest
from meta_pipeline.ledger import Ledger

def test_delegation_reconciliation_keeps_uncertain_child_hold_and_history(tmp_path):
    ledger=Ledger(str(tmp_path/'l'),100,100)
    key=ledger.reserve('root','model',100);ledger.settle(key,None,{'error_type':'remote_failure'})
    ledger.narrow_unresolved_delegation(key,20,'a'*64)
    assert ledger.summary()['states'][0]['accounted_nusd']==20
    ledger.reserve('root','model',80)
    with pytest.raises(ValueError):ledger.reserve('root','model',1)
    with ledger.connect()as db:
        assert db.execute('SELECT before_reserved,retained_reserved FROM reconciliations').fetchone()==(100,20)
        assert db.execute('SELECT charged,state FROM calls WHERE id=?',(key,)).fetchone()==(None,'unresolved')
    with pytest.raises(ValueError):ledger.narrow_unresolved_delegation(key,30,'b'*64)
