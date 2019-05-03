module Dradis
  module Plugins
    module Burp
      class Engine < ::Rails::Engine
        isolate_namespace Dradis::Plugins::Burp

        include ::Dradis::Plugins::Base
        description 'Processes Burp Scanner output'
        provides :upload

        # Because this plugin provides two export modules, we have to overwrite
        # the default .uploaders() method.
        #
        # See:
        #  Dradis::Plugins::Upload::Base in dradis-plugins
        def self.uploaders
          [
            Dradis::Plugins::Burp::Html,
            Dradis::Plugins::Burp::Xml
          ]
        end

        # We define Dadis::Plugins::Burp::[Html/Xml]::Engine
        # But we still want the plugin name to be 'burp' 
        def self.plugin_name
          'burp'
        end
      end
    end
  end
end
