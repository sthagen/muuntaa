"""Named protocol to ensure common interfaces for the subtrees."""

import logging
from typing import Any, Protocol

import lxml.objectify  # nosec B410

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
