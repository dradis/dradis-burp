module Burp
  module Html
  # This class represents each of the issue elements in the Burp
  # Scanner HTML document: all elemennts from a span.BODH0 until the next
  # span.BODH0 (the next one excluded).
  #
  # It provides a convenient way to access the information scattered all over
  # the HTML.
  class Issue < ::Burp::Issue
    # Accepts a Nokogiri::XML::NodeSet
    def initialize(html)
      @html = Nokogiri::HTML(html.to_s)
    end

    # List of supported tags
    def supported_tags
      [
        # tags with contents retrieved from inside the span header
        :name, :type,

        # tags with contents retrieved following the span header
        :background, :detail,
        :references, :remediation_background, :remediation_detail,
        :request, :request_1, :request_2, :request_3,
        :response, :response_1, :response_2, :response_3,
        :vulnerability_classifications
      ] + summary_table_tags
    end

    def header
      @header ||= @html.at_css('span')
    end

    def name
      @name ||= header.text.gsub(/^\d+\.\S/, '')
    end

    # Link looks like: https://portswigger.net/kb/issues/00200400_flash-cross-domain-policy
    # We use that 00200400 as type since in that page it calls it 'Type index'
    def type
      @type ||=
        if header_link = header.at_css('a')
          header_link.attr('href').to_s[/\/([0-9a-f]+)_.*/, 1].to_i(16)
        else
          nil
        end
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

      # First we try the h2 headers.
      translations_table = {
        background: ['Issue background', 'Issue description'],
        detail: 'Issue detail',
        references: 'References',
        remediation_background: ['Remediation background', 'Issue remediation'],
        remediation_detail: 'Remediation detail',
        request: 'Request',
        request_1: 'Request 1',
        request_2: 'Request 2',
        request_3: 'Request 3',
        response: 'Response',
        response_1: 'Response 1',
        response_2: 'Response 2',
        response_3: 'Response 3',
        serial_number: 'Serial number',
        vulnerability_classifications: 'Vulnerability classifications'
      }

      # look for the h2 headers in the html fragment
      method_names = translations_table.fetch(method, method.to_s)
      method_names = [method_names].flatten

      h2 = nil
      method_names.each do |method_name|
        h2 = @html.xpath("//h2[text()='#{method_name}']").first
        break if h2
      end

      if h2
        content =
          if h2.text =~ /^(Request|Response)/
            cleanup_request_response_html(h2.next_element.inner_html)
          else
            cleanup_html(h2.next_element.inner_html)
          end

        return content
      end

      # look inside the summary table in the html fragment
      summary[method]
    end

    private

    # In Request/Response html snippets we don't want to cleanup the whole
    # html as we ususally do. The snippets may contain html code to be displayed,
    # and we don't want to convert that to textile.
    def cleanup_request_response_html(source)
      result = source.dup

      result.gsub!(/<b>(.*?)<\/b>/, '\1')
      result.gsub!(/<br>|<\/br>/){"\n"}
      result.gsub!(/<span.*?>/, '')
      result.gsub!(/<\/span>/, '')

      result.gsub!(/&quot;/, '"')
      result.gsub!(/&amp;/, '&')
      result.gsub!(/&lt;/, '<')
      result.gsub!(/&gt;/, '>')
      result.gsub!(/&nbsp;/, ' ')

      result
    end

    # Returns the summary table in the HTML fragment as a Hash
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
        :confidence, :host, :path, :severity
      ]
    end

  end
  end
end
