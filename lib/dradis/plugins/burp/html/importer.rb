module Dradis::Plugins::Burp
  # This module knows how to parse Burp HTML format.
  module Html
    def self.meta
      package = Dradis::Plugins::Burp
      {
        name:        package::Engine::plugin_name,
        description: 'Upload Burp Scanner output file (.html)',
        version:     package.version
      }
    end

    class Importer < Dradis::Plugins::Upload::Importer
      def initialize(args={})
        args[:plugin] = Dradis::Plugins::Burp
        super(args)
      end

      def import(params = {})
        logger.info { 'Parsing Burp Scanner HTML output file...' }
        @doc = Nokogiri::HTML(File.read(params[:file]))
        logger.info { 'Done.' }

        # Issue headers are like: <span class="BODH0" id="X">
        issue_headers = @doc.xpath("//span[contains(@class, 'BODH0')]")

        if issue_headers.count.zero?
          error = "Document doesn't seem to be in the Burp Scanner HTML format."
          logger.fatal { error }
          content_service.create_note text: error
          return false
        end

        issue_headers.each do |header|
          issue_id = header.attr('id')
          html     = extract_html_fragment_for(issue_id)
          process_html_issue(html)
        end

        logger.info { 'Burp Scanner results successfully imported' }
        true
      end

      def process_html_issue(html_issue)
        header     = html_issue.first
        title      = header.text.gsub(/^\d+\.\S/, '')
        burp_id =
          if (link = header.css('a').first)
            link.attr('href')[/\/([0-9a-f]+)_.*/, 1].to_i(16)
          else
            title
          end
        issue_id   = html_issue.attr('id').value
        issue_text =
          template_service.process_template(
            template: 'issue',
            data: html_issue
          )

        logger.info { "Processing issue #{issue_id}: #{title}" }
        issue = content_service.create_issue(text: issue_text, id: burp_id)

        # Evidence headers are like:
        #   <span class="BODH1" id="X.Y">
        # where:
        #   X is the issue index
        #   Y is the evidence index
        evidence_headers = html_issue.xpath(
          "//span[contains(@class, 'BODH1') and starts-with(@id, '#{issue_id}.')]"
        )

        # If there are no evidence headers inside this issue, this is a
        # "single evidence" case: our evidence html is the issue html itself
        if evidence_headers.count.zero?
          process_html_evidence(html_issue, issue)
        else
          evidence_headers.each do |header|
            evidence_id = header.attr('id')
            html = extract_html_fragment_for(evidence_id)
            process_html_evidence(html, issue)
          end
        end
      end

      def process_html_evidence(html_evidence, issue)
        evidence_id = html_evidence.attr('id').value
        logger.info { "Processing evidence #{evidence_id}" }

        host_td    = html_evidence.search("td:starts-with('Host:')").first
        host_label = host_td.next_element.text.split('//').last
        host       = content_service.create_node(label: host_label, type: :host)

        evidence_text =
          template_service.process_template(
            template: 'html_evidence',
            data: html_evidence
          )

        content_service.create_evidence(
          issue: issue,
          node: host,
          content: evidence_text
        )
      end

      # Html for an issue and evidence is not nested inside an html element.
      #
      # An issue is the html fragment from <span id="X"> (where X is a single
      # integer number: 1, 2, 3...) until the next span like that or the end of
      # the file.
      #
      # An evidence is the html fragment from <span id="X.Y"> (where X is the
      # issue index and Y the evidence index: 1.1, 1.2,...,2.1, 2.2,...) until
      # the next evidence span (id="X.Z"), the next issue span (id="Y"), or the
      # end of the file.
      #
      # This method extracts all the html related to as specific issue id or
      # evidence id.
      def extract_html_fragment_for(id)
        next_id = if /\d+\.\d+/ =~ id
                    id_parts = id.split('.')
                    "#{id_parts[0]}.#{id_parts[1].to_i + 1}"
                  else
                    id.to_i + 1
                  end

        start_element = @doc.xpath("//span[@id='#{id}']")
        return nil if start_element.empty?

        ending_element = @doc.xpath("//span[@id='#{next_id}']")
        if ending_element.empty? && /\d+\.\d+/ =~ id
          next_id = id.split('.')[0].to_i + 1
          ending_element = @doc.xpath("//span[@id='#{next_id}']")
        end

        xpath = "//*[preceding-sibling::span[@id='#{id}']"
        xpath += " and following-sibling::span[@id='#{next_id}']" unless ending_element.empty?
        xpath += ']'

        start_element + @doc.xpath(xpath)
      end
    end
  end
end
