module Dradis::Plugins::Burp
  class Importer < Dradis::Plugins::Upload::Importer

    # The framework will call this function if the user selects this plugin from
    # the dropdown list and uploads a file.
    # @returns true if the operation was successful, false otherwise
    def import(params = {})
      file_content = File.read( params[:file] )

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
      issue_types   = {}
      affected_host = nil
      issue_text    = nil
      evidence_text = nil

      doc.xpath('issues/issue').each do |xml_issue|
        issue_name = xml_issue.at('name').text
        issue_type = xml_issue.at('type').text.to_i

        logger.info{ "Adding #{issue_name} (#{issue_type})" }

        host_label = xml_issue.at('host')['ip']
        host_label = xml_issue.at('host').text if host_label.empty?
        affected_host = content_service.create_node(label: host_label, type: :host)
        logger.info{ "\taffects: #{host_label}" }

        if !hosts.include?(affected_host.label)
          url = xml_issue.at('host').text
          host_description = "\#[HostInfo]\#\n#{url}\n\n"
          content_service.create_note(text: host_description, node: affected_host)
        end

        # The first time we see a new issue type (i.e. Burp plugin ID), we create
        # a new Issue object for the general info (e.g. background, desc, recomm)
        # and an Evidence object for the instance especific bits.
        if !issue_types.key?( issue_type )
          logger.info{ "\tissue not found in the library yet. Adding..." }

          issue_text = template_service.process_template(
            template: 'issue',
            data: xml_issue)

          issue_types[ issue_type ] = content_service.create_issue(
            text: issue_text,
            id: issue_type)

          logger.info{ "\t\tdone."}
        end

        logger.info{ "\tadding evidence for this instance to #{affected_host.label}."}
        evidence_text = template_service.process_template(
          template: 'evidence',
          data: xml_issue)

        content_service.create_evidence(
          issue: issue_types[issue_type],
          node: affected_host,
          content: evidence_text)

        logger.info{ 'Burp Scanner results successfully imported' }
        return true
      end
    end

  end
end
