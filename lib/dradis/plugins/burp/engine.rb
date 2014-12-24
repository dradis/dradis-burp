module Dradis
  module Plugins
    module Burp
      class Engine < ::Rails::Engine
        isolate_namespace Dradis::Plugins::Burp

        include ::Dradis::Plugins::Base
        description 'Processes Burp Scanner XML output'
        provides :upload

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

