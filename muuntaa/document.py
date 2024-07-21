"""Document specific types: Leaves, Publisher, and Tracking."""

import logging
import operator
from typing import Any, Union

import lxml.objectify  # nosec B410

from muuntaa.config import boolify
from muuntaa.dialect import PUBLISHER_TYPE_CATEGORY, TRACKING_STATUS
from muuntaa.strftime import get_utc_timestamp
from muuntaa.subtree import Subtree

from muuntaa import APP_ALIAS, ConfigType, NOW_CODE, VERSION, VERSION_PATTERN, cleanse_id, integer_tuple

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
        category = PUBLISHER_TYPE_CATEGORY.get(root.attrib.get('Type', ''))  # TODO consistent key error handling?
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

    fix_insert_current_version_into_revision_history: bool = False

    def __init__(self, config: ConfigType):
        super().__init__()
        boolify(config)
        self.fix_insert_current_version_into_revision_history = config.get(  # type: ignore
            'fix_insert_current_version_into_revision_history', False
        )
        print(f'{self.fix_insert_current_version_into_revision_history=}')
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
        status = TRACKING_STATUS.get(root.Status.text, '')  # type: ignore
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
    def only_version_t(revision_history: RevHistType) -> bool:
        """Verifies whether all version numbers in /document/tracking/revision_history comply."""
        return all(VERSION_PATTERN.match(revision['number']) for revision in revision_history)  # type: ignore

    def _add_current_revision_to_history(self, root: RootType, revision_history: RevHistType) -> None:
        """Adds the current version to history, if former is missing in latter and fix is requested.

        The user can request the fix per --fix-insert-current-version-into-revision-history option
        or per setting the respective configuration key to true.
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
        revision_history = [
            {
                'date': get_utc_timestamp(revision.Date.text or ''),  # type: ignore
                'number': revision.Number.text,  # type: ignore # may be patched later (in case of mismatches)
                'summary': revision.Description.text,  # type: ignore
                'number_cvrf': revision.Number.text,  # type: ignore # keep track of original value (later matching)
                'version_as_int_tuple': integer_tuple(revision.Number.text or ''),  # type: ignore # temporary
            }
            for revision in root.RevisionHistory.Revision
        ]
        version = root.Version.text

        missing_latest_version_in_history = False
        if not [rev for rev in revision_history if rev['number'] == version]:  # Current version not in rev. history?
            if self.fix_insert_current_version_into_revision_history:
                self._add_current_revision_to_history(root, revision_history)
                level = logging.WARNING
                message = (
                    'Trying to fix the revision history by adding the current version.'
                    ' This may lead to inconsistent history.'
                    ' This happens because --fix-insert-current-version-into-revision-history is used.'
                )
            else:
                missing_latest_version_in_history = True
                self.error_occurred = True
                level = logging.ERROR
                message = (
                    'Current version is missing in revision history.'
                    ' This can be fixed by using --fix-insert-current-version-into-revision-history.'
                )
            logging.log(level, message)

        if not self.only_version_t(revision_history):  # one or more versions do not comply
            if missing_latest_version_in_history:
                self.error_occurred = True
                logging.error(
                    'Can not reindex revision history to integers because of missing the current version.'
                    ' This can be fixed with --fix-insert-current-version-into-revision-history'
                )
            else:  # sort and replace version values with rank as per conformance rule
                revision_history, version = self._reindex_versions_to_integers(root, revision_history)

        for revision in revision_history:  # remove temporary fields
            revision.pop('number_cvrf')
            revision.pop('version_as_int_tuple')

        return revision_history, version
