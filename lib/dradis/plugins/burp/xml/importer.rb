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
        doc = Nokogiri::XML(file_content)
        logger.info { 'Done.' }

        if doc.root.name != 'issues'
          error = "Document doesn't seem to be in the Burp Scanner XML format."
          logger.fatal { error }
          content_service.create_note text: error
          return false
        end

        # This will be filled in by the Processor while iterating over the issues
        @hosts         = []
        @affected_host = nil
        @issue_text    = nil
        @evidence_text = nil

        doc.xpath('issues/issue').each do |xml_issue|
          process_issue(xml_issue)
        end

        logger.info { 'Burp Scanner results successfully imported' }
        true
      end

      # Creates the Nodes/properties
      def process_issue(xml_issue)
        host_label = xml_issue.at('host')['ip']
        host_label = xml_issue.at('host').text if host_label.empty?
        affected_host = content_service.create_node(label: host_label, type: :host)
        logger.info { "\taffects: #{host_label}" }

        unless @hosts.include?(affected_host.label)
          @hosts << affected_host.label
          url = xml_issue.at('host').text
          affected_host.set_property(:hostname, url)
          affected_host.save
        end

        # Burp extensions don't follow the "unique type for every Issue" logic
        # so we have to deal with them separately
        burp_extension_type = '134217728'.freeze
        if xml_issue.at('type').text.to_str == burp_extension_type
          process_extension_issues(affected_host, xml_issue)
        else
          process_burp_issues(affected_host, xml_issue)
        end
      end

      # If the Issues come from the Burp app, use the type as the plugin_ic
      def process_burp_issues(affected_host, xml_issue)
        issue_name = xml_issue.at('name').text
        issue_type = xml_issue.at('type').text.to_i

        logger.info { "Adding #{issue_name} (#{issue_type})" }

        create_issue(
          affected_host: affected_host,
          id: issue_type,
          xml_issue: xml_issue
        )
      end

      # If the Issues come from a Burp extension (type = 134217728), then
      # use the name (spaces removed) as the plugin_id
      def process_extension_issues(affected_host, xml_issue)
        ext_name = xml_issue.at('name').text
        ext_name = ext_name.gsub!(" ", "")

        logger.info { "Adding #{ext_name}" }

        create_issue(
          affected_host: affected_host,
          id: ext_name,
          xml_issue: xml_issue
        )
      end

      def create_issue(affected_host:, id:, xml_issue:)
        issue_text =
          template_service.process_template(
            template: 'issue',
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
          template_service.process_template(
            template: 'evidence',
            data: xml_issue
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
    end
  end
end
