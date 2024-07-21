import logging

from lxml import objectify

from muuntaa.refs import References

CFG = {
    'csaf_version': '2.0',
    'fix_insert_current_version_into_revision_history': 'true',
}

HAS_TL_REFERENCES_XML = """\
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
   <DocumentReferences>
     <Reference Type="Self">
     <URL>https://example.com/sec/vendorix-sa-20170301-abc</URL>
     <Description>Vendorix Foo AppY...</Description>
     </Reference>
   </DocumentReferences>
</cvrfdoc>
"""

ROOT_HAS_TL_REFERENCES = objectify.fromstring(HAS_TL_REFERENCES_XML)


def test_tl_references(caplog):
    expected = {
        'document': {
            'references': [
                {
                    'category': 'self',
                    'summary': 'Vendorix Foo AppY...',
                    'url': 'https://example.com/sec/vendorix-sa-20170301-abc',
                }
            ],
        },
    }

    part = References(config=CFG, lc_parent_code='cvrf')
    caplog.set_level(logging.INFO)
    part.load(ROOT_HAS_TL_REFERENCES.DocumentReferences)
    assert not part.has_errors()
    assert part.dump() == expected
    assert not caplog.text
