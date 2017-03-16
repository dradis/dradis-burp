module Dradis
  module Plugins
    module Burp
      class Engine < ::Rails::Engine
        isolate_namespace Dradis::Plugins::Burp

        include ::Dradis::Plugins::Base
        description 'Processes Burp Scanner XML output'
        provides :upload
      end
    end
  end
end

