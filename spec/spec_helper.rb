require 'rubygems'
require 'bundler/setup'
require 'nokogiri'
require 'combustion'

Combustion.initialize!

RSpec.configure do |config|
  # Enable colors
  config.color = true
  # Use the specified formatter
  config.formatter = :documentation
end
