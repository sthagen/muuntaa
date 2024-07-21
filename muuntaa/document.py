"""Document specific types: Leaves, Publisher, and Tracking."""

import logging
import operator
import re
from typing import Any, Union

import lxml.objectify  # nosec B410

from muuntaa.config import boolify
from muuntaa.strftime import get_utc_timestamp
from muuntaa.subtree import Subtree

from muuntaa import APP_ALIAS, ConfigType, NOW_CODE, VERSION, cleanse_id, integer_tuple

RootType = lxml.objectify.ObjectifiedElement
RevHistType = list[dict[str, Union[str, None, tuple[int, ...]]]]


class Leafs(Subtree):
    """Represent leaf element content below CSAF path.

    (
        /document,
    )
    """

    def __init__(self, config: ConfigType) -> None:
        super().__init__()
        if self.tree.get('document') is None:
            self.tree['document'] = {}
        self.hook = self.tree['document']
        self.hook['csaf_version'] = config.get('csaf_version')

    def always(self, root: RootType) -> None:
        self.hook['category'] = root.DocumentType.text
        self.hook['title'] = root.DocumentTitle.text

    def sometimes(self, root: RootType) -> None:
        if doc_dist := root.DocumentDistribution is not None:
            self.hook['distribution'] = {'text': doc_dist.text}  # type: ignore

        if agg_sev := root.AggregateSeverity is not None:
            self.hook['aggregate_severity'] = {'text': agg_sev.text}  # type: ignore
            if agg_sev_ns := root.AggregateSeverity.attrib.get('Namespace') is not None:
                self.hook['aggregate_severity']['namespace'] = agg_sev_ns


class Publisher(Subtree):
    """Represents the Publisher type:

    (
        /cvrf:cvrfdoc/cvrf:DocumentPublisher,
    )
    """

    CATEGORY_OF = {
        'Coordinator': 'coordinator',
        'Discoverer': 'discoverer',
        'Other': 'other',
        'User': 'user',
        'Vendor': 'vendor',
    }

    def __init__(self, config: ConfigType):
        super().__init__()
        if self.tree.get('document') is None:
            self.tree['document'] = {}
        if self.tree['document'].get('publisher') is None:
            self.tree['document']['publisher'] = {
                'name': config.get('publisher_name'),
                'namespace': config.get('publisher_namespace'),
            }
        self.hook = self.tree['document']['publisher']

    def always(self, root: RootType) -> None:
        category = self.CATEGORY_OF.get(root.attrib.get('Type', ''))
        self.hook['category'] = category

    def sometimes(self, root: RootType) -> None:
        if contact_details := root.ContactDetails:
            self.hook['contact_details'] = contact_details.text
        if issuing_authority := root.IssuingAuthority:
            self.hook['issuing_authority'] = issuing_authority.text


class Tracking(Subtree):
    """Represents the Tracking type.
    (
        /cvrf:cvrfdoc/cvrf:DocumentTracking,
    )
    """

    STATUS_OF = {'Draft': 'draft', 'Final': 'final', 'Interim': 'interim'}

    fix_insert_current_version_into_revision_history: bool = False

    def __init__(self, config: ConfigType):
        super().__init__()
        boolify(config)
        self.fix_insert_current_version_into_revision_history = config.get(  # type: ignore
            'fix_insert_current_version_into_revision_history', False
        )
        processing_ts, problems = get_utc_timestamp(ts_text=NOW_CODE)
        for level, problem in problems:
            logging.log(level, problem)
        if self.tree.get('document') is None:
            self.tree['document'] = {}
        if self.tree['document'].get('tracking') is None:
            self.tree['document']['tracking'] = {
                'generator': {
                    'date': processing_ts,
                    'engine': {
                        'name': APP_ALIAS,
                        'version': VERSION,
                    },
                },
            }
        self.hook = self.tree['document']['tracking']

    def always(self, root: RootType) -> None:
        current_release_date, problems = get_utc_timestamp(root.CurrentReleaseDate.text or '')
        for level, problem in problems:
            logging.log(level, problem)
        initial_release_date, problems = get_utc_timestamp(root.InitialReleaseDate.text or '')
        for level, problem in problems:
            logging.log(level, problem)
        revision_history, version = self._handle_revision_history_and_version(root)
        status = self.STATUS_OF.get(root.Status.text, '')  # type: ignore
        self.hook['current_release_date'] = current_release_date
        self.hook['id'] = cleanse_id(root.Identification.ID.text or '')
        self.hook['initial_release_date'] = initial_release_date
        self.hook['revision_history'] = revision_history
        self.hook['status'] = status
        self.hook['version'] = version

    def sometimes(self, root: RootType) -> None:
        if aliases := root.Identification.Alias:
            self.hook['aliases'] = [alias.text for alias in aliases]

    @staticmethod
    def check_for_version_t(revision_history: RevHistType) -> bool:
        """
        Checks whether all version numbers in /document/tracking/revision_history match
        semantic versioning. Semantic version is defined in version_t definition.
        see: https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#3111-version-type
        and section 9.1.5 Conformance Clause 5: CVRF CSAF converter
        """

        pattern = (
            r'^((0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)'
            r'(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)'
            r'(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))'
            r'?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)$'
        )
        return all(re.match(pattern, revision['number']) for revision in revision_history)  # type: ignore

    def _add_current_revision_to_history(self, root: RootType, revision_history: RevHistType) -> None:
        """
        If the current version is missing in Revision history and
        --fix-insert-current-version-into-revision-history is True,
        the current version is added to the history.
        """

        entry_date, problems = get_utc_timestamp(root.CurrentReleaseDate.text or '')
        for level, problem in problems:
            logging.log(level, problem)
        revision_history.append(
            {
                'date': entry_date,
                'number': root.Version.text,
                'summary': f'Added by {APP_ALIAS} as the value was missing in the original CVRF.',
                'number_cvrf': root.Version.text,  # Helper field
                'version_as_int_tuple': integer_tuple(root.Version.text or ''),  # Helper field
            }
        )

    @staticmethod
    def _reindex_versions_to_integers(root: RootType, revision_history: RevHistType) -> tuple[RevHistType, str]:
        logging.warning(
            'Some version numbers in revision_history do not match semantic versioning. Reindexing to integers.'
        )

        revision_history_sorted = sorted(revision_history, key=operator.itemgetter('version_as_int_tuple'))

        for rev_number, revision in enumerate(revision_history_sorted, start=1):
            revision['number'] = str(rev_number)
            # add property legacy_version with the original version number
            # for each reindexed version
            revision['legacy_version'] = revision['number_cvrf']

        # after reindexing, match document version to corresponding one in revision history
        version = next(rev for rev in revision_history_sorted if rev['number_cvrf'] == root.Version.text)['number']

        return revision_history_sorted, version  # type: ignore

    def _handle_revision_history_and_version(self, root: RootType) -> tuple[list[dict[str, Any]], str | None]:
        # preprocess the data
        revision_history = []
        for revision in root.RevisionHistory.Revision:
            # number_cvrf: keep original value in this variable for matching later
            # number: this value might be overwritten later if some version numbers doesn't match
            # semantic versioning
            revision_history.append(
                {
                    'date': get_utc_timestamp(revision.Date.text or ''),  # type: ignore
                    'number': revision.Number.text,  # type: ignore
                    'summary': revision.Description.text,  # type: ignore
                    # Extra vars
                    'number_cvrf': revision.Number.text,  # type: ignore
                    'version_as_int_tuple': integer_tuple(revision.Number.text or ''),  # type: ignore
                }
            )

        # Just copy over the version
        version = root.Version.text

        missing_latest_version_in_history = False
        # Do we miss the current version in the revision history?
        if not [rev for rev in revision_history if rev['number'] == version]:
            if self.fix_insert_current_version_into_revision_history:
                logging.warning(
                    'Trying to fix the revision history by adding the current version. '
                    'This may lead to inconsistent history. This happens because '
                    '--fix-insert-current-version-into-revision-history is used. '
                )
                self._add_current_revision_to_history(root, revision_history)
            else:
                logging.error(
                    'Current version is missing in revision history. This can be fixed by'
                    ' using --fix-insert-current-version-into-revision-history.'
                )
                missing_latest_version_in_history = True
                self.error_occurred = True

        # handle corresponding part of Conformance Clause 5: CVRF CSAF converter
        # that is: some version numbers in revision_history don't match semantic versioning
        if not self.check_for_version_t(revision_history):
            if not missing_latest_version_in_history:
                revision_history, version = self._reindex_versions_to_integers(root, revision_history)
            else:
                logging.error(
                    'Can not reindex revision history to integers because of missing'
                    ' the current version. This can be fixed with'
                    ' --fix-insert-current-version-into-revision-history'
                )
                self.error_occurred = True

        # cleanup extra vars
        for revision in revision_history:  # type: ignore
            revision.pop('number_cvrf')  # type: ignore
            revision.pop('version_as_int_tuple')  # type: ignore

        return revision_history, version
