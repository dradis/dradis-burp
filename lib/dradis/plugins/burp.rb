module Dradis
  module Plugins
    module Burp
      # This is required while we transition the Upload Manager to use
      # Dradis::Plugins
      module Meta
        NAME = "Burp Scanner output (.xml) file upload"
        EXPECTS = "Burp Scanner XML output. Go to the Scanner tab > right-click item > generate report"
        module VERSION
          include Dradis::Plugins::Burp::VERSION
        end
      end
    end
  end
end

require 'dradis/plugins/burp/engine'
require 'dradis/plugins/burp/field_processor'
require 'dradis/plugins/burp/importer'
require 'dradis/plugins/burp/version'