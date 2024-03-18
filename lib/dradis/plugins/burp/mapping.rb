module Dradis::Plugins::Burp
  module Mapping
    DEFAULT_MAPPING = {
      html_evidence: {
        'Host' => '{{ burp[issue.host] }}',
        'Path' => '{{ burp[issue.path] }}',
        'Location' => '{{ burp[issue.location] }}',
        'Severity' => '{{ burp[issue.severity] }}',
        'Confidence' => '{{ burp[issue.confidence] }}',
        'Request' => 'bc.. {{ burp[issue.request] }}',
        'Response' => 'bc.. {{ burp[issue.response] }}',
        'Request 1' => 'bc.. {{ burp[issue.request_1] }}',
        'Response 1' => 'bc.. {{ burp[issue.response_1] }}',
        'Request 2' => 'bc.. {{ burp[issue.request_2] }}',
        'Response 2' => 'bc.. {{ burp[issue.response_2] }}',
        'Request 3' => 'bc.. {{ burp[issue.request_3] }}',
        'Response 3' => 'bc.. {{ burp[issue.response_3] }}'
      },
      html_issue: {
        'Title' => '{{ burp[issue.name] }}',
        'Severity' => '{{ burp[issue.severity] }}',
        'Background' => '{{ burp[issue.background] }}',
        'RemediationBackground' => '{{ burp[issue.remediation_background] }}',
        'Detail' => '{{ burp[issue.detail] }}',
        'RemediationDetails' => '{{ burp[issue.remediation_detail] }}',
        'References' => '{{ burp[issue.references] }}',
        'Classifications' => '{{ burp[issue.vulnerability_classifications] }}'
      },
      xml_evidence: {
        'Host' => '{{ burp[issue.host] }}',
        'Path' => '{{ burp[issue.path] }}',
        'Location' => '{{ burp[issue.location] }}',
        'Severity' => '{{ burp[issue.severity] }}',
        'Confidence' => '{{ burp[issue.confidence] }}',
        'Request' => 'bc.. {{ burp[issue.request] }}',
        'Response' => 'bc.. {{ burp[issue.response] }}',
        'Request 1' => 'bc.. {{ burp[issue.request_1] }}',
        'Response 1' => 'bc.. {{ burp[issue.response_1] }}',
        'Request 2' => 'bc.. {{ burp[issue.request_2] }}',
        'Response 2' => 'bc.. {{ burp[issue.response_2] }}',
        'Request 3' => 'bc.. {{ burp[issue.request_3] }}',
        'Response 3' => 'bc.. {{ burp[issue.response_3] }}'
      },
      xml_issue: {
        'Title' => '{{ burp[issue.name] }}',
        'Severity' => '{{ burp[issue.severity] }}',
        'Background' => '{{ burp[issue.background] }}',
        'RemediationBackground' => '{{ burp[issue.remediation_background] }}',
        'Detail' => '{{ burp[issue.detail] }}',
        'RemediationDetails' => '{{ burp[issue.remediation_detail] }}',
        'References' => '{{ burp[issue.references] }}',
        'Classifications' => '{{ burp[issue.vulnerability_classifications] }}'
      }
    }.freeze
  end
end
