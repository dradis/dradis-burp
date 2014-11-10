module Burp
  # This class represents each of the /issues/issue elements in the Burp
  # Scanner XML document.
  #
  # It provides a convenient way to access the information scattered all over
  # the XML in attributes and nested tags.
  #
  # Instead of providing separate methods for each supported property we rely
  # on Ruby's #method_missing to do most of the work.
  class Issue
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
        :serial_number, :type, :name, :host, :path, :location, :severity,
        :confidence, :background, :remediation_background, :detail,
        :remediation_detail,

        # nested tags
        :request, :response
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
        :background => 'issueBackground',
        :detail => 'issueDetail',
        :remediation_background => 'remediationBackground',
        :remediation_detail => 'remediationDetail',
        :serial_number => 'serialNumber'
      }

      method_name = translations_table.fetch(method, method.to_s)

      # no attributes in the <issue> node
      # return @xml.attributes[method_name].value if @xml.attributes.key?(method_name)

      # Then we try simple children tags: name, type, ...
      tag = @xml.xpath("./#{method_name}").first
      if tag
        return tag.text
      end

      if (['request', 'response'].include?(method_name))
        requestresponse_child(method_name)
      else
        # nothing found, the tag is valid but not present in this ReportItem
        return nil
      end
    end

    private
    def requestresponse_child(field)
      return 'n/a' unless @xml.at('requestresponse') && @xml.at("requestresponse/#{field}")

      xml_node = @xml.at("requestresponse/#{field}")
      result = "[unprocessable #{field}]"

      if xml_node['base64'] == 'true'
        result = Base64::decode64(xml_node.text)
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
      result.truncate(50000, :omission => '... (truncated)')
    end
  end
end