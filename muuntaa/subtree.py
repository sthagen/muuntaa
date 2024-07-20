import logging
from typing import Any, Protocol

import lxml.objectify  # nosec B410

from muuntaa.config import boolify
from muuntaa import ConfigType

RootType = lxml.objectify.ObjectifiedElement


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
