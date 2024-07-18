import logging
from typing import Any, Protocol

import lxml.objectify

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
    """Represent leaf element content below CSAF path (/document)."""

    def __init__(self, config: dict[str, str]) -> None:
        super().__init__()
        self.tree['csaf_version'] = config.get('csaf_version')

    def always(self, root: RootType) -> None:
        self.tree['category'] = root.DocumentType.text
        self.tree['title'] = root.DocumentTitle.text

    def sometimes(self, root: RootType) -> None:
        if doc_dist := root.DocumentDistribution:
            self.tree['distribution'] = {'text': doc_dist.text}

        if agg_sev := root.AggregateSeverity:
            self.tree['aggregate_severity'] = {'text': agg_sev.text}
            if agg_sev_ns := root.AggregateSeverity.attrib.get('Namespace'):
                self.tree['aggregate_severity']['namespace'] = agg_sev_ns
