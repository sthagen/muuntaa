"""Products type."""

import logging

import lxml.objectify  # nosec B410

from muuntaa.dialect import BRANCH_TYPE, RELATION_TYPE
from muuntaa.subtree import Subtree

RootType = lxml.objectify.ObjectifiedElement


class Products(Subtree):
    """Represents the Products type.

    (
        /cvrf:cvrfdoc/prod:ProductTree,
    )
    """

    def __init__(self) -> None:
        super().__init__()
        if self.tree.get('product_tree') is None:
            self.tree['product_tree'] = {}
        self.hook = self.tree['product_tree']

    def always(self, root: RootType) -> None:
        pass

    def sometimes(self, root: RootType) -> None:
        self._handle_full_product_names(root)
        self._handle_relationships(root)
        self._handle_product_groups(root)

        branches = self._handle_branches_recursive(root)
        if branches is not None:
            self.hook['branches'] = branches

    @staticmethod
    def _get_full_product_name(fpn_elem: RootType) -> dict[str, dict[str, str]]:
        fpn = {'product_id': fpn_elem.attrib['ProductID'], 'name': fpn_elem.text}

        if fpn_elem.attrib.get('CPE'):
            fpn['product_identification_helper'] = {'cpe': fpn_elem.attrib['CPE']}  # type: ignore

        return fpn  # type: ignore

    @classmethod
    def _get_branch_type(cls, branch_type: str):  # type: ignore
        if branch_type in ['Realm', 'Resource']:
            logging.warning(
                'Input branch type %s is no longer supported in CSAF. Converting to product_name', branch_type
            )

        return BRANCH_TYPE[branch_type]  # TODO implement consistent key error reaction strategy

    def _handle_full_product_names(self, root: RootType) -> None:
        if full_product_name := root.FullProductName:
            self.hook['full_product_names'] = [
                self._get_full_product_name(fpn_elem) for fpn_elem in full_product_name  # type: ignore
            ]

    def _handle_relationships(self, root: RootType) -> None:
        if relationship := root.Relationship:
            relationships = []
            for entry in relationship:
                # Take the first entry only as the full_product_name.
                first_prod_name = entry.FullProductName[0]  # type: ignore
                if len(entry.FullProductName) > 1:  # type: ignore
                    # ... in addition, log a warning on information loss during conversion of product relationships.
                    logging.warning(
                        'Input line %s: Relationship contains more FullProductNames.'
                        ' Taking only the first one, since CSAF expects only 1 value here',
                        entry.sourceline,
                    )
                rel_to_add = {
                    'category': RELATION_TYPE[entry.attrib['RelationType']],  # type: ignore
                    'product_reference': entry.attrib['ProductReference'],
                    'relates_to_product_reference': entry.attrib['RelatesToProductReference'],
                    'full_product_name': self._get_full_product_name(first_prod_name),
                }
                relationships.append(rel_to_add)

            self.hook['relationships'] = relationships

    def _handle_product_groups(self, root: RootType) -> None:
        if product_groups := root.ProductGroups:
            records = []
            for product_group in product_groups.Group:
                product_ids = [x.text for x in product_group.ProductID]  # type: ignore
                record = {
                    'group_id': product_group.attrib['GroupID'],
                    'product_ids': product_ids,
                }
                if summary := product_group.Description:  # type: ignore
                    record['summary'] = summary.text
                records.append(record)

            self.hook['product_groups'] = records

    def _handle_branches_recursive(self, root: RootType):  # type: ignore
        """Process the branches (any branch can contain either list of other branches or a single FullProductName)."""
        if not root.Branch and not root.FullProductName:
            return None  # No branches to process

        if 'Branch' in root.tag and (full_product_name := root.FullProductName):
            # Inside Branch (not in the top ProductTree element, where FullProductName can also occur)
            leaf_branch = {
                'name': root.attrib['Name'],
                'category': self._get_branch_type(root.attrib['Type']),  # type: ignore
                'product': self._get_full_product_name(full_product_name),
            }
            return leaf_branch  # Current root is the leaf branch

        if branch := root.Branch:
            branches = []
            for entry in branch:
                if entry.FullProductName:  # type: ignore
                    branches.append(self._handle_branches_recursive(entry))  # type: ignore
                else:
                    branches.append(
                        {
                            'name': entry.attrib['Name'],
                            'category': self._get_branch_type(entry.attrib['Type']),  # type: ignore
                            'branches': self._handle_branches_recursive(entry),  # type: ignore
                        }
                    )
            return branches
