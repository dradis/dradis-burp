module Dradis::Plugins::Burp

  # This module knows how to parse Burp XML format.
  module Xml
    def self.meta
      package = Dradis::Plugins::Burp
      {
        name:        package::Engine::plugin_name,
        description: 'Upload Burp Scanner output file (.xml)',
        version:     package.version
      }
    end

    class Importer < Dradis::Plugins::Upload::Importer
      BURP_EXTENSION_TYPE = '134217728'.freeze
      BURP_SEVERITIES     = ['Information', 'Low', 'Medium', 'High'].freeze

      def self.templates
        { evidence: 'xml_evidence', issue: 'xml_issue' }
      end

      def initialize(args={})
        args[:plugin] = Dradis::Plugins::Burp
        super(args)
      end

      def import(params = {})
        file_content = File.read(params[:file])

        if file_content =~ /base64="false"/
          error =  "Burp input contains HTTP request / response data that hasn't been Base64-encoded.\n"
          error << 'Please re-export your scanner results making sure the Base-64 encode option is selected.'

          logger.fatal{ error }
          content_service.create_note text: error
          return false
        end

        logger.info { 'Parsing Burp Scanner XML output file...' }
        doc = Nokogiri::XML(file_content) { |config| config.huge }
        logger.info { 'Done.' }

        if doc.root.name != 'issues'
          error = 'Document doesn\'t seem to be in the Burp Scanner XML format.'
          logger.fatal { error }
          content_service.create_note text: error
          return false
        end

        # This will be filled in by the Processor while iterating over the issues
        @issues     = []
        @severities = Hash.new(0)

        # We need to look ahead through all issues to bring the highest severity
        # of each instance to the Issue level.
        doc.xpath('issues/issue').each do |xml_issue|
          issue_id       = issue_id_for(xml_issue)
          issue_severity = BURP_SEVERITIES.index(xml_issue.at('severity').text)

          @severities[issue_id] = issue_severity if issue_severity > @severities[issue_id]
          @issues << xml_issue
        end

        @issues.each { |xml_issue| process_issue(xml_issue) }

        logger.info { 'Burp Scanner results successfully imported' }
        true
      end

      private
      def create_issue(affected_host:, id:, xml_issue:)
        xml_evidence = xml_issue.clone

        # Ensure that the Issue contains the highest Severity value
        xml_issue.at('severity').content = BURP_SEVERITIES[@severities[id]]

        issue_text =
          mapping_service.apply_mapping(
            source: 'xml_issue',
            data: xml_issue
          )

        if issue_text.include?(::Burp::INVALID_UTF_REPLACE)
          logger.info do
            "\tdetected invalid UTF-8 bytes in your issue. " \
            "Replacing them with '#{::Burp::INVALID_UTF_REPLACE}'."
          end
        end

        issue = content_service.create_issue(text: issue_text, id: id)

        logger.info do
          "\tadding evidence for this instance to #{affected_host.label}."
        end

        evidence_text =
          mapping_service.apply_mapping(
            source: 'xml_evidence',
            data: xml_evidence
          )

        if evidence_text.include?(::Burp::INVALID_UTF_REPLACE)
          logger.info do
            "\tdetected invalid UTF-8 bytes in your evidence. " \
            "Replacing them with '#{::Burp::INVALID_UTF_REPLACE}'."
          end
        end

        content_service.create_evidence(
          issue: issue,
          node: affected_host,
          content: evidence_text
        )
      end

      # Burp extensions don't follow the "unique type for every Issue" logic
      # so we have to deal with them separately
      def issue_id_for(xml_issue)
        if xml_issue.at('type').text == BURP_EXTENSION_TYPE
          xml_issue.at('name').text.gsub!(' ', '')
        else
          xml_issue.at('type').text.to_i
        end
      end

      # Creates the Nodes/properties
      def process_issue(xml_issue)
        host_url   = xml_issue.at('host').text
        host_label = xml_issue.at('host')['ip']
        host_label = host_url if host_label.empty?
        issue_id   = issue_id_for(xml_issue)

        affected_host = content_service.create_node(label: host_label, type: :host)
        affected_host.set_property(:hostname, host_url)
        affected_host.save

        logger.info { "Adding #{xml_issue.at('name').text} (#{issue_id})"}
        logger.info { "\taffects: #{host_label}" }

        create_issue(
          affected_host: affected_host,
          id: issue_id,
          xml_issue: xml_issue
        )
      end
    end
  end
end
