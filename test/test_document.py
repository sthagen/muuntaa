import logging

from lxml import objectify

from muuntaa.document import Publisher, Tracking
from muuntaa import APP_ALIAS, VERSION

CFG = {
    'csaf_version': '2.0',
    'fix_insert_current_version_into_revision_history': 'true',
}
CFG_TOO = {
    'publisher_name': 'Publisher Name',
    'publisher_namespace': 'https://example.com',
}

HAS_TL_PUBLISHER_XML = """\
<cvrfdoc
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:cpe="http://cpe.mitre.org/language/2.0"
  xmlns:cvrf="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"
  xmlns:cvrf-common="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/common"
  xmlns:cvssv2="http://scap.nist.gov/schema/cvss-v2/1.0"
  xmlns:cvssv3="https://www.first.org/cvss/cvss-v3.0.xsd"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:ns0="http://purl.org/dc/elements/1.1/"
  xmlns:prod="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/prod"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/1.0"
  xmlns:sch="http://purl.oclc.org/dsdl/schematron"
  xmlns:vuln="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"
  >
  <!-- Document wide context information -->
  <DocumentTitle>AppY Stream Control Transmission Protocol</DocumentTitle>
  <DocumentType>Security Advisory</DocumentType>
  <DocumentPublisher Type="Vendor">
      <ContactDetails>Emergency Support: ...</ContactDetails>
      <IssuingAuthority>... Team (PSIRT)....</IssuingAuthority>
  </DocumentPublisher>
</cvrfdoc>
"""

HAS_TL_TRACKING_XML = """\
<cvrfdoc
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:cpe="http://cpe.mitre.org/language/2.0"
  xmlns:cvrf="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"
  xmlns:cvrf-common="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/common"
  xmlns:cvssv2="http://scap.nist.gov/schema/cvss-v2/1.0"
  xmlns:cvssv3="https://www.first.org/cvss/cvss-v3.0.xsd"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:ns0="http://purl.org/dc/elements/1.1/"
  xmlns:prod="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/prod"
  xmlns:scap-core="http://scap.nist.gov/schema/scap-core/1.0"
  xmlns:sch="http://purl.oclc.org/dsdl/schematron"
  xmlns:vuln="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns="http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/cvrf"
  >
  <!-- Document wide context information -->
  <DocumentTitle>AppY Stream Control Transmission Protocol</DocumentTitle>
  <DocumentType>Security Advisory</DocumentType>
  <DocumentTracking>
    <Identification>
      <ID>vendorix-sa-20170301-abc</ID>
    </Identification>
    <Status>Final</Status>
    <Version>1.0</Version>
    <RevisionHistory>
      <Revision>
        <Number>1.0</Number>
        <Date>2017-03-01T14:58:48</Date>
        <Description>Initial public release.</Description>
      </Revision>
    </RevisionHistory>
    <InitialReleaseDate>2017-03-01T16:00:00</InitialReleaseDate>
    <CurrentReleaseDate>2017-03-01T14:58:48</CurrentReleaseDate>
    <Generator>
      <Engine>TVCE</Engine>
    </Generator>
  </DocumentTracking>
</cvrfdoc>
"""

ROOT_HAS_TL_PUBLISHER = objectify.fromstring(HAS_TL_PUBLISHER_XML)
ROOT_HAS_TL_TRACKING = objectify.fromstring(HAS_TL_TRACKING_XML)


def test_tl_publisher(caplog):
    expected = {
        'document': {
            'publisher': {
                'category': 'vendor',
                'contact_details': 'Emergency Support: ...',
                'issuing_authority': '... Team (PSIRT)....',
                'name': 'Publisher Name',
                'namespace': 'https://example.com',
            },
        },
    }

    part = Publisher(config=CFG_TOO)
    caplog.set_level(logging.INFO)
    part.load(ROOT_HAS_TL_PUBLISHER.DocumentPublisher)
    assert not part.has_errors()
    assert part.dump() == expected
    assert not caplog.text


def test_tl_tracking(caplog):
    expected = {
        'document': {
            'tracking': {
                'current_release_date': '2017-03-01T14:58:48.000+00:00',
                'generator': {
                    'date': None,
                    'engine': {
                        'name': APP_ALIAS,
                        'version': VERSION,
                    },
                },
                'id': 'vendorix-sa-20170301-abc',
                'initial_release_date': '2017-03-01T16:00:00.000+00:00',
                'revision_history': [
                    {
                        'date': (
                            '2017-03-01T14:58:48.000+00:00',
                            [],
                        ),
                        'legacy_version': '1.0',
                        'number': '1',
                        'summary': 'Initial public release.',
                    },
                ],
                'status': 'final',
                'version': '1',
            },
        },
    }

    part = Tracking(config=CFG)
    caplog.set_level(logging.ERROR)
    part.load(ROOT_HAS_TL_TRACKING.DocumentTracking)
    assert not part.has_errors()
    part_dump = part.dump()
    expected['document']['tracking']['generator']['date'] = part_dump['document']['tracking']['generator']['date']
    assert part_dump == expected
    assert 'Alias' in caplog.text
