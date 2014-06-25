module Dradis
  module Plugins
    module Burp
      class Engine < ::Rails:Engine
        include ::Dradis::Plugins::Base

        isolate_namespace Dradis::Plugins::Burp


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