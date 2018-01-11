module Dradis::Plugins::Burp
  class Importer < Dradis::Plugins::Upload::Importer

    # The framework will call this function if the user selects this plugin from
    # the dropdown list and uploads a file.
    # @returns true if the operation was successful, false otherwise
    def import(params = {})
      file_content = File.read( params[:file] )

      if file_content =~ /base64="false"/
        error =  "Burp input contains HTTP request / response data that hasn't been Base64-encoded.\n"
        error << "Please re-export your scanner results making sure the Base-64 encode option is selected."

        logger.fatal{ error }
        content_service.create_note text: error
        return false
      end

      logger.info{ 'Parsing Burp Scanner output file...' }
      doc = Nokogiri::XML( file_content )
      logger.info{'Done.'}

      if doc.root.name != 'issues'
        error = "Document doesn't seem to be in the Burp Scanner XML format."
        logger.fatal{ error }
        content_service.create_note text: error
        return false
      end

      # This will be filled in by the Processor while iterating over the issues
      hosts         = []
      affected_host = nil
      issue_text    = nil
      evidence_text = nil

      doc.xpath('issues/issue').each do |xml_issue|
        issue_name = xml_issue.at('name').text
        issue_type = xml_issue.at('type').text.to_i

        logger.info{ "Adding #{ issue_name } (#{ issue_type })" }

        host_label = xml_issue.at('host')['ip']
        host_label = xml_issue.at('host').text if host_label.empty?
        affected_host = content_service.create_node(label: host_label, type: :host)
        logger.info{ "\taffects: #{ host_label }" }

        if !hosts.include?(affected_host.label)
          hosts << affected_host.label
          url = xml_issue.at('host').text
          affected_host.set_property(:hostname, url)
          affected_host.save
        end

        issue_text = template_service.process_template(
          template: 'issue',
          data: xml_issue)

        if issue_text.include?(::Burp::INVALID_UTF_REPLACE)
          logger.info %{
            "\tdetected invalid UTF-8 bytes in your issue. " \
            "Replacing them with '#{::Burp::INVALID_UTF_REPLACE}'."
          }
        end

        issue = content_service.create_issue(
          text: issue_text,
          id: issue_type)

        logger.info{ "\tadding evidence for this instance to #{ affected_host.label }."}

        evidence_text = template_service.process_template(
          template: 'evidence',
          data: xml_issue
        )

        if evidence_text.include?(::Burp::INVALID_UTF_REPLACE)
          logger.info {
            "\tdetected invalid UTF-8 bytes in your evidence. " \
            "Replacing them with '#{::Burp::INVALID_UTF_REPLACE}'."
          }
        end

        content_service.create_evidence(
          issue: issue,
          node: affected_host,
          content: evidence_text
        )

      end
      logger.info{ 'Burp Scanner results successfully imported' }
      return true
    end

  end
end
