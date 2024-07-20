import logging
from typing import Union

import lxml.objectify  # nosec B410

from muuntaa.config import boolify
from muuntaa.subtree import Subtree
from muuntaa import ConfigType

RootType = lxml.objectify.ObjectifiedElement
RevHistType = list[dict[str, Union[str, None, tuple[int, ...]]]]


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
