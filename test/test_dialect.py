import muuntaa.dialect as dialect


def test_branch_trans():
    branch_trans = dialect.branch_trans
    for cvrf, csaf in dialect.BRANCH_TYPE.items():
        assert branch_trans.late(cvrf) == csaf
    assert branch_trans.late('not_found') is None


def test_publisher_type_category_trans():
    publisher_type_category_trans = dialect.publisher_type_category_trans
    for cvrf, csaf in dialect.PUBLISHER_TYPE_CATEGORY.items():
        assert publisher_type_category_trans.late(cvrf) == csaf
    assert publisher_type_category_trans.late('not_found') is None


def test_relation_trans():
    relation_trans = dialect.relation_trans
    for cvrf, csaf in dialect.RELATION_TYPE.items():
        assert relation_trans.late(cvrf) == csaf
    assert relation_trans.late('not_found') is None


def test_remediation_trans():
    remediation_trans = dialect.remediation_trans
    for cvrf, csaf in dialect.REMEDIATION_CATEGORY.items():
        assert remediation_trans.late(cvrf) == csaf
    assert remediation_trans.late('not_found') is None


def test_score_cvss_v2_trans():
    score_cvss_v2_trans = dialect.score_cvss_v2_trans
    for cvrf, csaf in dialect.SCORE_CVSS_V2.items():
        assert score_cvss_v2_trans.late(cvrf) == csaf
    assert score_cvss_v2_trans.late('not_found') is None


def test_score_cvss_v3_trans():
    score_cvss_v3_trans = dialect.score_cvss_v3_trans
    for cvrf, csaf in dialect.SCORE_CVSS_V3.items():
        assert score_cvss_v3_trans.late(cvrf) == csaf
    assert score_cvss_v3_trans.late('not_found') is None


def test_tracking_status_trans():
    tracking_status_trans = dialect.tracking_status_trans
    for cvrf, csaf in dialect.TRACKING_STATUS.items():
        assert tracking_status_trans.late(cvrf) == csaf
    assert tracking_status_trans.late('not_found') is None
