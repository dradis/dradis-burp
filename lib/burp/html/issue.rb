module Burp
  module Html
  # We use this string to replace invalid UTF-8 bytes with.
  # INVALID_UTF_REPLACE = '<?>'

  # This class represents each of the issue elements in the Burp
  # Scanner HTML document: all elemennts from a span.BODH0 until the next
  # span.BODH0 (the next one excluded).
  #
  # It provides a convenient way to access the information scattered all over
  # the HTML.
  class Issue < ::Burp::Issue
    # Accepts a Nokogiri::XML::NodeSet
    def initialize(html)
      @html = html
    end

    # List of supported tags
    def supported_tags
      [
        # tags with contents retrieved from inside the span header
        :type, :name,

        # tags with contents retrieved following the span header
        :background, :remediation_background, :detail,
        :remediation_detail, :references, :vulnerability_classifications,
        :request_1, :request_2, :request_3,
        :response_1, :response_2, :response_3
      ] + summary_table_tags
    end

    def name
      @html.first.css('a').text
    end

    def link
      @html.first.css('a').attr('href').value
    end

    # Link looks like: https://portswigger.net/kb/issues/00200400_flash-cross-domain-policy
    # We use that 00200400 as type since in that page it calls it 'Type index'
    def type
      link[/\/(\d+)_.*/, 1]
    end

    # This method is invoked by Ruby when a method that is not defined in this
    # instance is called.
    #
    # In our case we inspect the @method@ parameter and try to find the
    # corresponding header in our HTML, then return the following text.
    def method_missing(method, *args)
      # We could remove this check and return nil for any non-recognized tag.
      # The problem would be that it would make tricky to debug problems with
      # typos. For instance: <>.potr would return nil instead of raising an
      # exception
      unless supported_tags.include?(method)
        super
        return
      end

      # First we try the attributes. In Ruby we use snake_case, but in XML
      # CamelCase is used for some attributes
      translations_table = {
        background: 'Issue background',
        detail: 'Issue detail',
        remediation_background: 'Remediation background',
        remediation_detail: 'Remediation detail',
        vulnerability_classifications: 'Vulnerability classifications',
        serial_number: 'Serial number',
        request_1: 'Request 1',
        response_1: 'Response 1',
        request_2: 'Request 2',
        response_2: 'Response 2',
        request_3: 'Request 3',
        response_3: 'Response 3'
      }

      # look for the h2 headers in the html fragment
      method_name = translations_table.fetch(method, method.to_s)
      h2 = @html.xpath("//h2[text()='#{method_name}']").first
      unless h2.nil?
        h2.next_element.css('br').each { |br| br.replace("\n") }
        return cleanup_html(h2.next_element.text)
      end

      # look inside the summary table in the html fragment
      summary[method]
    end

    private

    def summary
      @summary ||= begin
        @summary = {}
        h2 = @html.search("h2[text()='Summary']").first
        return @summary if h2.nil?

        table = h2.next_element

        summary_table_tags.each do |tag|
          td = table.search("td:starts-with('#{tag.to_s.capitalize}:')").first
          @summary[tag] = td.next_element.text
        end

        @summary
      end
    end

    # List of supported tags to obtain from the summary html table
    def summary_table_tags
      [
        :host, :severity, :path, :confidence
      ]
    end

  end
  end
end
