import logging
from typing import Protocol


class Subtree(Protocol):

    def __init__(self):
        self.tree = {}

    def always(self, root) -> None:
        pass

    def sometimes(self, root) -> None:
        pass

    def load(self, root) -> None:
        try:
            self.always(root)
        except Exception as e:
            logging.error('ingesting always present element %s failed with %s', root.tag, e)
        try:
            self.sometimes(root)
        except Exception as e:
            logging.error('ingesting sometimes present element %s failed with %s', root.tag, e)

    def dump(self) -> dict[str, object]:
        return self.tree


class DocumentLeafs(Subtree):
    """Represent leaf element content below CSAF path (/document)."""

    def __init__(self, config):
        super().__init__()
        self.csaf_version = config.get('csaf_version')

    def always(self, root):
        # This element is new in CSAF, not present in CVRF
        self.tree['csaf_version'] = self.csaf_version

        self.tree['category'] = root.DocumentType.text
        self.tree['title'] = root.DocumentTitle.text

    def sometimes(self, root):
        if doc_dist := root.DocumentDistribution:
            self.tree['distribution'] = {'text': doc_dist.text}

        if agg_sev := root.AggregateSeverity:
            self.tree['aggregate_severity'] = {'text': agg_sev.text}
            if agg_sev_ns := root.AggregateSeverity.attrib.get('Namespace'):
                self.tree['aggregate_severity']['namespace'] = agg_sev_ns
