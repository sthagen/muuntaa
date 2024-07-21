import logging

from lxml import objectify

from muuntaa.notes import Notes

HAS_TL_NOTES_XML = """\
<?xml version='1.0'?>
<cvrfdoc xmlns:cpe="http://cpe.mitre.org/language/2.0"
   xmlns:cvrf="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"
   xmlns:cvrf-common="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/common"
   xmlns:cvssv2="http://scap.nist.gov/schema/cvss-v2/1.0"
   xmlns:cvssv3="https://www.first.org/cvss/cvss-v3.0.xsd"
   xmlns:dc="http://purl.org/dc/elements/1.2/"
   xmlns:ns0="http://purl.org/dc/elements/1.1/"
   xmlns:prod="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/prod"
   xmlns:scap-core="http://scap.nist.gov/schema/scap-core/1.0"
   xmlns:sch="http://purl.oclc.org/dsdl/schematron"
   xmlns:vuln="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf">

   <!-- Document wide context information -->
   <DocumentTitle xml:lang="en">Acme Security Advisory for foo on bar - March 2017 - CSAF CVRF</DocumentTitle>
   <DocumentType xml:lang="en">Acme Security Advisory</DocumentType>
   <DocumentNotes>
      <Note Audience="All" Ordinal="1" Title="Summary" Type="Summary" xml:lang="en">
         This document contains descriptions of Acme product security vulnerabilities with details on impacted ...
         Additional information regarding ... be found at the Acme sites referenced in this document.</Note>
   </DocumentNotes>
</cvrfdoc>
"""

ROOT_HAS_TL_NOTES = objectify.fromstring(HAS_TL_NOTES_XML)


def test_tl_notes(caplog):
    expected = {
        'document': {
            'notes': [
                {
                    'text': (
                        '\n'
                        '         This document contains descriptions of Acme product security vulnerabilities with'
                        ' details on impacted ...\n'
                        '         Additional information regarding ... be found at the Acme sites referenced in'
                        ' this document.'
                    ),
                    'category': 'summary',
                    'audience': 'All',
                    'title': 'Summary',
                }
            ],
        },
    }

    part = Notes(lc_parent_code='cvrf')
    caplog.set_level(logging.ERROR)
    part.load(ROOT_HAS_TL_NOTES.DocumentNotes)
    assert not part.has_errors()
    assert part.dump() == expected
    assert not caplog.text
