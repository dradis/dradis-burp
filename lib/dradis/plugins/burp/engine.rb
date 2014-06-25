module Dradis
  module Plugins
    module Burp
      class Engine < ::Rails::Engine
        isolate_namespace Dradis::Plugins::Burp

        include ::Dradis::Plugins::Base
        provides :upload

#     NAME = "Burp Scanner output (.xml) file upload"
    # EXPECTS = "Burp Scanner XML output. Go to the Scanner tab > right-click item > generate report"


        # Configuring the gem
        # class Configuration < Core::Configurator
        #   configure :namespace => 'burp'
        #   setting :category, :default => 'Burp Scanner output'
        #   setting :author, :default => 'Burp Scanner plugin'
        # end

      end
    end
  end
end