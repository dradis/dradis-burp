module Dradis
  module Plugins
    module Burp
      class FieldProcessor < Dradis::Plugins::Upload::FieldProcessor

        def post_initialize(args={})
          @burp_object =
            if data.is_a?(Nokogiri::XML::Element)
              ::Burp::Xml::Issue.new(data)
            else # Nokogiri::XML::NodeSet
              ::Burp::Html::Issue.new(data)
            end
        end

        def value(args={})
          field = args[:field]
          # fields in the template are of the form <foo>.<field>, where <foo>
          # is common across all fields for a given template (and meaningless).
          _, name = field.split('.')

          @burp_object.try(name) || 'n/a'
        end

      end
    end
  end
end
