$:.push File.expand_path('../lib', __FILE__)

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.platform      = Gem::Platform::RUBY
  s.name = 'dradis-burp'
  s.version = '3.0.0'
  s.summary = 'Burp Scanner upload plugin for the Dradis Framework.'
  s.description = 'This plugin allows you to upload and parse output produced from Portswigger\'s Burp Scanner into Dradis.'

  s.license = 'GPL-2'

  s.authors = ['Daniel Martin']
  s.email = ['etd@nomejortu.com']
  s.homepage = 'http://dradisframework.org'

  s.files = `git ls-files`.split($\)
  s.executables = s.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  s.add_dependency 'rails', '~> 4.1.1'
  s.add_dependency 'dradis_core', '~> 3.0'
  s.add_dependency 'dradis-plugins', '~> 3.0'
end
