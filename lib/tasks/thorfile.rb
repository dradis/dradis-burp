class BurpTasks < Thor
  include Rails.application.config.dradis.thor_helper_module

  namespace "dradis:plugins:burp"

  desc "upload FILE", "upload Burp XML results"
  def upload(file_path)
    require 'config/environment'

    unless File.exists?(file_path)
      $stderr.puts "** the file [#{file_path}] does not exist"
      exit -1
    end

    detect_and_set_project_scope

    importer = Dradis::Plugins::Burp::Importer.new(task_options)
    importer.import(file: file_path)
  end

end
