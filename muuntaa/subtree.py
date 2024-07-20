import logging
import operator
import re
from typing import Any, Protocol, Union

import lxml.objectify  # nosec B410

from muuntaa.config import boolify
from muuntaa.strftime import get_utc_timestamp
from muuntaa import APP_ALIAS, ConfigType, NOW_CODE, VERSION, cleanse_id, integer_tuple

RootType = lxml.objectify.ObjectifiedElement
RevHistType = list[dict[str, Union[str, None, tuple[int, ...]]]]


class Subtree(Protocol):
    tree: dict[str, Any] = None  # type: ignore
    some_error: bool = False

    def __init__(self) -> None:
        self.tree = {}
        self.some_error = False

    def always(self, root: RootType) -> None:
        pass

    def sometimes(self, root: RootType) -> None:
        pass

    def load(self, root: RootType) -> None:
        try:
            self.always(root)
        except Exception as e:
            logging.error('ingesting always present element %s failed with %s', root.tag, e)
        try:
            self.sometimes(root)
        except Exception as e:
            logging.error('ingesting sometimes present element %s failed with %s', root.tag, e)

    def dump(self) -> dict[str, Any]:
        return self.tree

    def has_errors(self) -> bool:
        return self.some_error


class DocumentLeafs(Subtree):
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


class Acknowledgments(Subtree):
    """Represent any Acknowledgments objects.

    (
        /cvrf:cvrfdoc/cvrf:Acknowledgments,
        /cvrf:cvrfdoc/vuln:Vulnerability[i+1]/vuln:Acknowledgments,
    )
    """

    def __init__(self, lc_parent_code: str):  # TODO: unlitter me and push data upstream
        super().__init__()
        if lc_parent_code not in ('cvrf', 'vuln'):
            raise KeyError('Acknowledgments can only be hosted by cvrf or vuln')
        if lc_parent_code == 'cvrf':
            if self.tree.get('document') is None:
                self.tree['document'] = {}
            if self.tree['document'].get('acknowledgments') is None:
                self.tree['document']['acknowledgments'] = []
            self.hook = self.tree['document']['acknowledgments']
        else:
            if self.tree.get('vulnerabilities') is None:
                self.tree['vulnerabilities'] = {}
            if self.tree['vulnerabilities'].get('acknowledgments') is None:
                self.tree['vulnerabilities']['acknowledgments'] = []
            self.hook = self.tree['vulnerabilities']['acknowledgments']

    def always(self, root: RootType) -> None:
        if root.Acknowledgment is not None:  # Acknowledgments if present shall not be empty in CSAF
            pass  # All fields optional per CVRF v1.2

    def sometimes(self, root: RootType) -> None:
        for ack in root.Acknowledgment:
            print(ack)
            if not any((ack.Name, ack.Organization, ack.Description, ack.URL)):  # type: ignore
                logging.warning('Skipping empty Acknowledgment entry, input line: %s', ack.sourceline)
                continue

            record = {}

            if orga := ack.Organization:  # type: ignore
                record['organization'] = orga[0].text
                if len(orga) > 1:
                    logging.warning(
                        'CSAF 2.0 allows only one organization inside Acknowledgments. '
                        'Taking the first occurence, ignoring: %s.',
                        orga[1:],
                    )

            if desc := ack.Description:  # type: ignore
                record['summary'] = desc[0].text  # Single Description elem is asserted on the input

            if names := ack.Name:  # type: ignore
                record['names'] = [name.text for name in names]  # Names can have more entries

            if urls := ack.URL:  # type: ignore
                record['urls'] = [url.text for url in urls]  # URLs can have more entries

            self.hook.append(record)


class Notes(Subtree):
    """Represent any Notes objects.

    (
        /cvrf:cvrfdoc/cvrf:DocumentNotes,
      - /cvrf:cvrfdoc/vuln:Vulnerability[i+1]/vuln:Notes,
    )
    """

    ENUM_CATEGORIES = {'description', 'details', 'faq', 'general', 'legal_disclaimer', 'other', 'summary'}
    ENUM_MSG = ','.join(ENUM_CATEGORIES)

    def __init__(self, lc_parent_code: str):  # TODO: unlitter me and push data upstream
        super().__init__()
        if lc_parent_code not in ('cvrf', 'vuln'):
            raise KeyError('Notes can only be hosted by cvrf or vuln')
        if lc_parent_code == 'cvrf':
            if self.tree.get('document') is None:
                self.tree['document'] = {}
            if self.tree['document'].get('notes') is None:
                self.tree['document']['notes'] = []
            self.hook = self.tree['document']['notes']
        else:
            if self.tree.get('vulnerabilities') is None:
                self.tree['vulnerabilities'] = {}
            if self.tree['vulnerabilities'].get('notes') is None:
                self.tree['vulnerabilities']['notes'] = []
            self.hook = self.tree['vulnerabilities']['notes']

    def always(self, root: RootType) -> None:
        for data in root.Note:
            category = data.attrib.get('Type', '').lower().replace(' ', '_')
            record = {  # always
                'text': data.text,
                'category': category,
            }
            if category not in self.ENUM_CATEGORIES:
                logging.error('Invalid document notes category %s. Should be one of: %s!', category, self.ENUM_MSG)
                self.some_error = True
            if audience := data.attrib.get('Audience'):  # sometimes
                record['audience'] = audience
            if title := data.attrib.get('Title'):  # sometimes
                record['title'] = title
            self.hook.append(record)

    def sometimes(self, root: RootType) -> None:
        pass


class References(Subtree):
    """Represents the References objects.

    (
        /cvrf:cvrfdoc/cvrf:DocumentReferences,
        /cvrf:cvrfdoc/vuln:Vulnerability[i+1]/vuln:References,
    )
    """

    force_default_category: bool = False

    def __init__(self, config: ConfigType, lc_parent_code: str):  # TODO: unlitter me and push data upstream
        super().__init__()
        boolify(config)
        self.force_default_category = config.get('force_insert_default_reference_category', False)  # type: ignore
        if lc_parent_code not in ('cvrf', 'vuln'):
            raise KeyError('References can only be hosted by cvrf or vuln')
        if lc_parent_code == 'cvrf':
            if self.tree.get('document') is None:
                self.tree['document'] = {}
            if self.tree['document'].get('references') is None:
                self.tree['document']['references'] = []
            self.hook = self.tree['document']['references']
        else:
            if self.tree.get('vulnerabilities') is None:
                self.tree['vulnerabilities'] = {}
            if self.tree['vulnerabilities'].get('references') is None:
                self.tree['vulnerabilities']['references'] = []
            self.hook = self.tree['vulnerabilities']['references']

    def always(self, root: RootType) -> None:
        for reference in root.Reference:
            ref_csaf = {
                'summary': reference.Description.text,  # type: ignore
                'url': reference.URL.text,  # type: ignore
            }
            if category := reference.attrib.get('Type', ''):
                ref_csaf['category'] = category.lower()
            elif self.force_default_category:
                ref_csaf['category'] = 'external'
                logging.info(
                    '"Type" attribute not present in "Reference" element, using default value "external".'
                    ' This can be controlled by "force_insert_default_reference_category" option.'
                )
            self.hook.append(ref_csaf)

    def sometimes(self, root: RootType) -> None:
        pass


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
