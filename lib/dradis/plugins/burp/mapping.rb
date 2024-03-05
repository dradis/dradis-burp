module Dradis::Plugins::Burp
  module Mapping
    def self.default_mapping
    end

    # since renaming template files to use a consistent structure,
    # we need a reference to the old names in order to migrate the
    # .template files to mapping records in the db
    # { new_template_name => old_template_name }
    def self.legacy_mapping_reference
      {
        'html_evidence' => 'html_evidence',
        'html_issue' => 'issue',
        'xml_evidence' => 'evidence',
        'xml_issue' => 'issue'
      }
    end
  end
end
