"""Translate between topic values in CVRF and CSAF dialects."""

from dataclasses import dataclass
from typing import Union

BRANCH_TYPE = {
    'Architecture': 'architecture',
    'Host Name': 'host_name',
    'Language': 'language',
    'Legacy': 'legacy',
    'Patch Level': 'patch_level',
    'Product Family': 'product_family',
    'Product Name': 'product_name',
    'Product Version': 'product_version',
    'Realm': 'product_name',  # Does not exist in CSAF, closest match is product_name
    'Resource': 'product_name',  # Does not exist in CSAF, closest match is product_name
    'Service Pack': 'service_pack',
    'Specification': 'specification',
    'Vendor': 'vendor',
}

PUBLISHER_TYPE_CATEGORY = {
    'Coordinator': 'coordinator',
    'Discoverer': 'discoverer',
    'Other': 'other',
    'User': 'user',
    'Vendor': 'vendor',
}

RELATION_TYPE = {
    'Default Component Of': 'default_component_of',
    'Optional Component Of': 'optional_component_of',
    'External Component Of': 'external_component_of',
    'Installed On': 'installed_on',
    'Installed With': 'installed_with',
}

REMEDIATION_CATEGORY = {
    'Mitigation': 'mitigation',
    'None Available': 'none_available',
    'Vendor Fix': 'vendor_fix',
    'Will Not Fix': 'no_fix_planned',
    'Workaround': 'workaround',
}

SCORE_CVSS_V2 = {
    'BaseScoreV2': 'baseScore',
    'EnvironmentalScoreV2': 'environmentalScore',
    'TemporalScoreV2': 'temporalScore',
    'VectorV2': 'vectorString',
}

SCORE_CVSS_V3 = {
    'BaseScoreV3': 'baseScore',
    'EnvironmentalScoreV3': 'environmentalScore',
    'TemporalScoreV3': 'temporalScore',
    'VectorV3': 'vectorString',
}

TRACKING_STATUS = {
    'Draft': 'draft',
    'Final': 'final',
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
