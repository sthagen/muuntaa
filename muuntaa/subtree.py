import logging
from typing import Any, Protocol

import lxml.objectify  # nosec B410

RootType = lxml.objectify.ObjectifiedElement


class Subtree(Protocol):
    tree: dict[str, Any] = None  # type: ignore

    def __init__(self) -> None:
        self.tree = {}

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


class DocumentLeafs(Subtree):
    """Represent leaf element content below CSAF path.

    (
        /document,
    )
    """

    def __init__(self, config: dict[str, str]) -> None:
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
