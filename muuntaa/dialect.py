"""Translate between topic values in CVRF and CSAF dialects."""

from dataclasses import dataclass
from typing import Union

BRANCH_TYPE = {
    'Vendor': 'vendor',
    'Product Family': 'product_family',
    'Product Name': 'product_name',
    'Product Version': 'product_version',
    'Patch Level': 'patch_level',
    'Service Pack': 'service_pack',
    'Architecture': 'architecture',
    'Language': 'language',
    'Legacy': 'legacy',
    'Specification': 'specification',
    'Host Name': 'host_name',
    'Realm': 'product_name',  # Does not exist in CSAF, closest match is product_name
    'Resource': 'product_name',  # Does not exist in CSAF, closest match is product_name
}

PUBLISHER_TYPE_CATEGORY = {
    'Vendor': 'vendor',
    'Coordinator': 'coordinator',
    'User': 'user',
    'Discoverer': 'discoverer',
    'Other': 'other',
}

RELATION_TYPE = {
    'Default Component Of': 'default_component_of',
    'Optional Component Of': 'optional_component_of',
    'External Component Of': 'external_component_of',
    'Installed On': 'installed_on',
    'Installed With': 'installed_with',
}

REMEDIATION_CATEGORY = {
    'Workaround': 'workaround',
    'Mitigation': 'mitigation',
    'Vendor Fix': 'vendor_fix',
    'None Available': 'none_available',
    'Will Not Fix': 'no_fix_planned',
}

SCORE_CVSS_V2 = {
    'BaseScoreV2': 'baseScore',
    'TemporalScoreV2': 'temporalScore',
    'EnvironmentalScoreV2': 'environmentalScore',
    'VectorV2': 'vectorString',
}

SCORE_CVSS_V3 = {
    'BaseScoreV3': 'baseScore',
    'TemporalScoreV3': 'temporalScore',
    'EnvironmentalScoreV3': 'environmentalScore',
    'VectorV3': 'vectorString',
}

TRACKING_STATUS = {
    'Final': 'final',
    'Draft': 'draft',
    'Interim': 'interim',
}


@dataclass
class TopicalTrans:
    """Class for translating using a topic dialect map."""

    pairs: dict[str, str]
    not_found: Union[str, None] = None

    def late(self, term: str) -> str:
        """Play safe, when you trans.late(a_term)."""
        return self.pairs.get(term, self.not_found)  # type: ignore


branch_trans = TopicalTrans(BRANCH_TYPE)
publisher_type_category_trans = TopicalTrans(PUBLISHER_TYPE_CATEGORY)
relation_trans = TopicalTrans(RELATION_TYPE)
remediation_trans = TopicalTrans(REMEDIATION_CATEGORY)
score_cvss_v2_trans = TopicalTrans(SCORE_CVSS_V2)
score_cvss_v3_trans = TopicalTrans(SCORE_CVSS_V3)
tracking_status_trans = TopicalTrans(TRACKING_STATUS)
