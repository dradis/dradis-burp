require 'rubygems'
require 'bundler/setup'
require 'nokogiri'
require 'combustion'

Combustion.initialize!

RSpec.configure do |config|
end

class StubbedMappingService
  def apply_mapping(args)
    processor = Dradis::Plugins::Burp::FieldProcessor.new(data: args[:data])
    Dradis::Plugins::Burp::Mapping::SOURCE_FIELDS[args[:source].to_sym].map do |field|
      processor.value(field: field)
    end.join("\n")
  end
end
