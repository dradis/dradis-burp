class BurpTasks < Thor
  include Core::Pro::ProjectScopedTask if defined?(::Core::Pro)

  namespace "dradis:plugins:burp"

  desc "upload FILE", "upload Burp XML results"
  def upload(file_path)
    require 'config/environment'

    logger = Logger.new(STDOUT)
    logger.level = Logger::DEBUG

    unless File.exists?(file_path)
      $stderr.puts "** the file [#{file_path}] does not exist"
      exit -1
    end

    content_service = nil
    template_service = nil
    if defined?(Dradis::Pro)
      detect_and_set_project_scope
      content_service = Dradis::Pro::Plugins::ContentService.new(plugin: Dradis::Plugins::Burp)
      template_service = Dradis::Pro::Plugins::TemplateService.new(plugin: Dradis::Plugins::Burp)
    else
      content_service = Dradis::Plugins::ContentService.new(plugin: Dradis::Plugins::Burp)
      template_service = Dradis::Plugins::TemplateService.new(plugin: Dradis::Plugins::Burp)
    end

    importer = Dradis::Plugins::Burp::Importer.new(
                logger: logger,
       content_service: content_service,
      template_service: template_service
    )

    importer.import(file: file_path)

    logger.close
  end

end
