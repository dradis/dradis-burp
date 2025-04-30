class BurpTasks < Thor
  include Rails.application.config.dradis.thor_helper_module

  namespace "dradis:plugins:burp"

  desc "upload FILE", "upload Burp XML or HTML results"
  method_option :state,
    type: :string,
    desc: 'The state your issues will be created with. If not provided, the scope will be draft'
  def upload(file_path)
    require 'config/environment'

    unless File.exists?(file_path)
      $stderr.puts "** the file [#{file_path}] does not exist"
      exit(-1)
    end

    detect_and_set_project_scope

    importer =
      if File.extname(file_path) == '.xml'
        Dradis::Plugins::Burp::Xml::Importer.new(task_options)
      elsif File.extname(file_path) == '.html'
        Dradis::Plugins::Burp::Html::Importer.new(task_options)
      else
        $stderr.puts "** Unsupported file. Must be .xml or .html"
        exit(-2)
      end

    importer.import(file: file_path)
  end
end
