"""Notes type."""

import logging
from typing import Union

import lxml.objectify  # nosec B410

from muuntaa.subtree import Subtree

RootType = lxml.objectify.ObjectifiedElement
RevHistType = list[dict[str, Union[str, None, tuple[int, ...]]]]


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
