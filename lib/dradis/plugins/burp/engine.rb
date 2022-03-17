module Dradis::Plugins::Burp
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

    def self.template_names
      {
        Dradis::Plugins::Burp::Html => { evidence: 'html_evidence', issue: 'issue' },
        Dradis::Plugins::Burp::Xml => { evidence: 'evidence', issue: 'issue' }
      }
    end
  end
end
