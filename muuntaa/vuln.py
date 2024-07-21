"""Vulnerabilities type."""

import bisect
import logging
import re
from typing import Union, no_type_check

from collections import defaultdict
from itertools import chain

import lxml.objectify  # nosec B410

from muuntaa.ack import Acknowledgments
from muuntaa.dialect import SCORE_CVSS_V2, SCORE_CVSS_V3, REMEDIATION_CATEGORY
from muuntaa.notes import Notes
from muuntaa.refs import References
from muuntaa.strftime import get_utc_timestamp
from muuntaa.subtree import Subtree
from muuntaa import ConfigType

RootType = lxml.objectify.ObjectifiedElement
RevHistType = list[dict[str, Union[str, None, tuple[int, ...]]]]


class Vulnerabilities(Subtree):
    """Represents the Vulnerabilities type.

    (
        /cvrf:cvrfdoc/vuln:Vulnerability,
    )
    """

    def __init__(self, config: ConfigType):
        super().__init__()
        self.config = config
        self.remove_cvss_values_without_vector = config['remove_CVSS_values_without_vector']
        self.default_cvss_version = config['default_CVSS3_version']
        if self.tree.get('vulnerabilities') is None:
            self.tree['vulnerabilities'] = []
        self.hook = self.tree['vulnerabilities']

    def always(self, root: RootType) -> None:
        pass

    @no_type_check
    def _handle_involvements(self, root: RootType):
        involvements = []
        for involvement_elem in root.Involvement:
            involvement = {
                'party': involvement_elem.attrib['Party'].lower(),
                'status': involvement_elem.attrib['Status'].lower().replace(' ', '_'),
            }

            if hasattr(involvement_elem, 'Description'):
                involvement['summary'] = involvement_elem.Description.text
            involvements.append(involvement)

        return involvements

    @no_type_check
    def _handle_product_statuses(self, root: RootType):
        statuses = defaultdict(list)
        for status_elem in root.Status:
            status_type = status_elem.attrib['Type'].lower().replace(' ', '_')
            product_ids = [product_id.text for product_id in status_elem.ProductID]
            statuses[status_type].extend(product_ids)

        return statuses

    @no_type_check
    def _handle_threats(self, root: RootType):
        threats = []
        for threat_elem in root.Threat:
            threat = {
                'details': threat_elem.Description.text,
                'category': threat_elem.attrib['Type'].lower().replace(' ', '_'),
            }

            if product_ids := threat_elem.ProductID:
                threat['product_ids'] = [product_id.text for product_id in product_ids]

            if group_ids := threat_elem.GroupID:
                threat['group_ids'] = [group_id.text for group_id in group_ids]

            if 'Date' in threat_elem.attrib:
                threat['date'] = get_utc_timestamp(threat_elem.attrib['Date'])

            threats.append(threat)

        return threats

    @no_type_check
    def _handle_remediations(self, root: RootType, product_status):

        remediations = []
        for remediation_elem in root.Remediation:
            remediation = {
                'category': REMEDIATION_CATEGORY[remediation_elem.attrib['Type']],
                'details': remediation_elem.Description.text,
            }

            if entitlements := remediation_elem.Entitlement:
                remediation['entitlements'] = [entitlement.text for entitlement in entitlements]

            if url := remediation_elem.URL:
                remediation['url'] = url.text

            if product_ids := remediation_elem.ProductID:
                remediation['product_ids'] = [product_id.text for product_id in product_ids]

            if group_ids := remediation_elem.GroupID:
                remediation['group_ids'] = [group_id.text for group_id in group_ids]

            if not any(('product_ids' in remediation, 'group_ids' in remediation)):
                if product_status:  # try to fix
                    product_ids = Vulnerabilities._parse_affected_product_ids(product_status)

            if len(product_ids):
                remediation['product_ids'] = product_ids
            else:
                self.some_error = True
                logging.error('No product_ids or group_ids entries for remediation.')

            if 'Date' in remediation_elem.attrib:
                remediation['date'] = get_utc_timestamp(remediation_elem.attrib['Date'])

            remediations.append(remediation)

        return remediations

    @staticmethod
    def _base_score_to_severity(base_score: float) -> str:
        base_severity = ((0, 'NONE'), (3.9, 'LOW'), (6.9, 'MEDIUM'), (8.9, 'HIGH'), (10, 'CRITICAL'))
        return base_severity[bisect.bisect_right(base_severity, (base_score, ''))][1]

    @no_type_check
    def _parse_affected_product_ids(self, product_status):
        """Parses ProductIDs with the states 'known_affected', 'first_affected' or 'last_affected'
        from product_status.
        """
        states = ('known_affected', 'first_affected', 'last_affected')
        return sorted(
            set(affected_product_id for state in states for affected_product_id in product_status.get(state, []))
        )

    @no_type_check
    def _parse_score_set(self, score_set_element, mapping, version, json_property, product_status):
        """Parses ScoreSetV2 or ScoreSetV3 element."""
        cvss_score = {
            csaf: score_set_element.find(f'{{*}}{cvrf}').text
            for cvrf, csaf in mapping.items()
            if score_set_element.find(f'{{*}}{cvrf}')
        }

        scores = ['baseScore', 'temporalScore', 'environmentalScore']
        for score in scores:
            if cvss_score.get(score):
                cvss_score[score] = float(cvss_score[score])

        if json_property == 'cvss_v3':  # Only cvss_v3 has baseSeverity
            cvss_score['baseSeverity'] = self._base_score_to_severity(cvss_score['baseScore'])

        products = []
        if product_ids := score_set_element.ProductID:
            products = [product_id.text for product_id in product_ids]
        elif product_status:  # try fix missing product ids
            products = self._parse_affected_product_ids(product_status)

        if len(products) == 0:
            self.some_error = True
            logging.error('No product_id entry for CVSS score set.')

        # if missing, conversion fails unless remove_CVSS_values_without_vector is true
        # if remove_CVSS_values_without_vector is true, we just ignore the score_set
        if 'vectorString' not in cvss_score:
            if self.remove_cvss_values_without_vector:
                logging.warning(
                    'No CVSS vector string found on the input,'
                    ' ignoring ScoreSet element due to "remove_CVSS_values_without_vector" option.'
                )
                return None

            self.some_error = True
            logging.error('No CVSS vector string found on the input.')

        # DETERMINE CVSS v 3.x from namespace
        cvss_3_regex = r'.*cvss-v(3\.[01]).*'
        match = re.match(cvss_3_regex, score_set_element.tag)
        if match:
            version = match.groups()[0]

        # DETERMINE CVSS v 3.x from vector if present
        if 'vectorString' in cvss_score and json_property == 'cvss_v3':
            # Regex for determining the CVSS version
            regex = r'CVSS:(3\.[01]).*'
            match = re.match(regex, cvss_score['vectorString'])
            if not match:
                self.some_error = True
                logging.error('CVSS vector %s is not valid.', cvss_score['vectorString'])
            else:
                version = match.groups()[0]

        cvss_score['version'] = version

        score = {json_property: cvss_score, 'products': products}

        return score

    @no_type_check
    def _remove_cvssv3_duplicates(self, scores):
        """Removes products/cvssv3.x score sets for products having both v3.0 and v3.1 score.

        Three-step approach:

         - find products having both versions specified
         - remove those products from score set with version 3.0
         - removes score sets with no products
        """
        products_v3_1 = set(
            chain.from_iterable(
                [
                    score_set['products']
                    for score_set in scores
                    if 'cvss_v3' in score_set and score_set['cvss_v3']['version'] == '3.1'
                ]
            )
        )
        products_v3_0 = set(
            chain.from_iterable(
                [
                    score_set['products']
                    for score_set in scores
                    if 'cvss_v3' in score_set and score_set['cvss_v3']['version'] == '3.0'
                ]
            )
        )
        both_versions = products_v3_0.intersection(products_v3_1)

        for score_set in scores:
            if 'cvss_v3' in score_set and score_set['cvss_v3']['version'] == '3.0':
                score_set['products'] = [product for product in score_set['products'] if product not in both_versions]

        return [score_set for score_set in scores if len(score_set['products']) > 0]

    @no_type_check
    def _handle_scores(self, root: RootType, product_status):
        score_variants = (
            ('ScoreSetV2', SCORE_CVSS_V2, '2.0', 'cvss_v2'),
            ('ScoreSetV3', SCORE_CVSS_V3, self.default_cvss_version, 'cvss_v3'),
        )

        scores = []
        for score_variant, mapping, score_version, target in score_variants:
            for score_set in root.findall(f'{{*}}{score_variant}'):
                score = self._parse_score_set(score_set, mapping, score_version, target, product_status)
                if score is not None:
                    scores.append(score)

        return self._remove_cvssv3_duplicates(scores)

    def sometimes(self, root: RootType) -> None:
        vulnerability = {}
        if acknowledgments := root.Acknowledgments:
            acks = Acknowledgments(lc_parent_code='vuln')
            acks.load(acknowledgments)
            vulnerability['acknowledgments'] = acks.dump()

        if cve := root.CVE:
            # Note: "^CVE-[0-9]{4}-[0-9]{4,}$" differs from CVRF regex -> delegate to JSON Schema validation
            vulnerability['cve'] = cve.text  # type: ignore

        if cwes := root.CWE:
            if len(cwes) > 1:
                logging.warning('%s CWE elements found, using only the first one.', len(cwes))
            vulnerability['cwe'] = {'id': cwes[0].attrib['ID'], 'name': cwes[0].text}

        if discovery_date_in := root.DiscoveryDate:
            discovery_date, problems = get_utc_timestamp(discovery_date_in.text or '')
            for level, problem in problems:
                logging.log(level, problem)
            vulnerability['discovery_date'] = discovery_date  # type: ignore

        if vuln_id := root.ID:
            vulnerability['ids'] = [
                {'system_name': vuln_id.attrib['SystemName'], 'text': vuln_id.text},  # type: ignore
            ]

        if involvements := root.Involvements:
            vulnerability['involvements'] = self._handle_involvements(involvements)

        if notes_root := root.Notes:
            notes = Notes(lc_parent_code='vuln')
            notes.load(notes_root)
            vulnerability['notes'] = notes.dump()

        if product_statuses := root.ProductStatuses:
            vulnerability['product_status'] = self._handle_product_statuses(product_statuses)

        if references_root := root.References:
            references = References(config=self.config, lc_parent_code='vuln')
            references.load(references_root)
            vulnerability['references'] = references.dump()

        if release_date_in := root.ReleaseDate:
            release_date, problems = get_utc_timestamp(release_date_in.text or '')
            for level, problem in problems:
                logging.log(level, problem)
            vulnerability['release_date'] = release_date  # type: ignore

        if remediations := root.Remediations:
            product_status = vulnerability.get('product_status')
            vulnerability['remediations'] = self._handle_remediations(remediations, product_status)

        if scores_root := root.CVSSScoreSets:
            if len(scores := self._handle_scores(scores_root, vulnerability.get('product_status'))):
                vulnerability['scores'] = scores
            else:
                logging.warning('None of the ScoreSet elements parsed, removing "scores" entry from the output.')

        if threats := root.Threats:
            vulnerability['threats'] = self._handle_threats(threats)

        if title := root.Title:
            vulnerability['title'] = title.text  # type: ignore

        self.hook.append(vulnerability)
