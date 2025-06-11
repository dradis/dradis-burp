module Burp
  module Xml
    # This class represents each of the /issues/issue elements in the Burp
    # Scanner XML document.
    #
    # It provides a convenient way to access the information scattered all over
    # the XML in attributes and nested tags.
    #
    # Instead of providing separate methods for each supported property we rely
    # on Ruby's #method_missing to do most of the work.
    class Issue < ::Burp::Issue

      # Accepts an XML node from Nokogiri::XML.
      def initialize(xml_node)
        @xml = xml_node
      end

      # List of supported tags. They can be attributes, simple descendants or
      # collections (e.g. <references/>, <tags/>)
      def supported_tags
        [
          # attributes

          # simple tags
          :background, :confidence, :detail, :host, :location, :name, :path,
          :references, :remediation_background, :remediation_detail,
          :serial_number, :severity, :type,
          :vulnerability_classifications,

          # nested tags
          :request, :request_1, :request_2, :request_3,
          :response, :response_1, :response_2, :response_3,
        ]
      end

      # This method is invoked by Ruby when a method that is not defined in this
      # instance is called.
      #
      # In our case we inspect the @method@ parameter and try to find the
      # attribute, simple descendent or collection that it maps to in the XML
      # tree.
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
          background: 'issueBackground',
          detail: 'issueDetail',
          remediation_background: 'remediationBackground',
          remediation_detail: 'remediationDetail',
          vulnerability_classifications: 'vulnerabilityClassifications',
          serial_number: 'serialNumber'
        }

        method_name = translations_table.fetch(method, method.to_s)

        # Then we try simple children tags: name, type, ...
        tag = @xml.xpath("./#{method_name}").first
        if tag && !tag.text.blank?
          if tags_with_html_content.include?(method)
            return cleanup_html(tag.text)
          else
            return tag.text
          end
        end

        if (method_name.include?('request') || method_name.include?('response'))
          requestresponse_child(method_name)
        else
          # nothing found, the tag is valid but not present in this ReportItem
          return nil
        end
      end

      private

      # Some of the values have embedded HTML content that we need to strip
      def tags_with_html_content
        [:background, :detail, :remediation_background, :remediation_detail, :references, :vulnerability_classifications]
      end

      def requestresponse_child(field)
        # `field` is of the format: [request/response]_[index]
        # Ex: `response_1` or `request_2`
        field_name, index = field.split('_')
        index = index.to_i

        request_response_xml = @xml.at_xpath("requestresponse[#{index + 1}]")

        return 'n/a' unless request_response_xml

        xml_node = request_response_xml.at(field_name)
        result = "[unprocessable #{field}]"

        if xml_node['base64'] == 'true'
          result = Base64::strict_decode64(xml_node.text)

          # don't pass binary data to the DB.
          if result =~ /\0/
            header, _ = result.split("\r\n\r\n")
            result = header << "\r\n\r\n" << '[Binary Data Not Displayed]'
          end
        else
          result = xml_node.text
        end

        # Just in case a null byte was left by Burp
        result.gsub!(/\0/,'&#00;')

        # We truncate the request/response because it can be pretty big.
        # If it is > 1M MySQL will die when trying to INSERT
        #
        # TODO: maybe add a reference to this node's XPATH so the user can go
        # back to the burp scanner file and look up the original request/response
        result.truncate(50000, omission: '... (truncated)')

        # Encode the string to UTF-8 to catch invalid bytes.
        result.encode('utf-8', invalid: :replace, undef: :replace, replace: ::Burp::INVALID_UTF_REPLACE)
      end
    end
  end
end
