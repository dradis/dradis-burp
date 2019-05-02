require 'dradis/plugins/burp/formats/xml'
require 'dradis/plugins/burp/formats/html'

module Dradis::Plugins::Burp
  class Importer < Dradis::Plugins::Upload::Importer

    include Formats::Xml
    include Formats::Html

    # The framework will call this function if the user selects this plugin from
    # the dropdown list and uploads a file.
    # @returns true if the operation was successful, false otherwise
    def import(params = {})
      file_content = File.read(params[:file])

      if file_content =~ /base64="false"/
        error =  "Burp input contains HTTP request / response data that hasn't been Base64-encoded.\n"
        error << 'Please re-export your scanner results making sure the Base-64 encode option is selected.'

        logger.fatal{ error }
        content_service.create_note text: error
        return false
      end

      if File.extname(params[:file]) == '.html'
        import_html(file_content)
      elsif File.extname(params[:file]) == '.xml'
        import_xml(file_content)
      end
    end
  end
end
