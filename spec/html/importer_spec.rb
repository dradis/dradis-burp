require 'spec_helper'
require 'ostruct'

describe 'Burp upload plugin' do
  describe Dradis::Plugins::Burp::Html::Importer do
    before(:each) do
      # Stub mappings service
      allow(Dradis::Plugins::MappingService).to receive(:new).and_return(
        StubbedMappingService.new
      )

      # Init services
      plugin = Dradis::Plugins::Burp::Html

      @content_service = Dradis::Plugins::ContentService::Base.new(
        logger: Logger.new(STDOUT),
        plugin: plugin
      )

      @importer = plugin::Importer.new(
        content_service: @content_service,
      )

      # Stub dradis-plugins methods
      #
      # They return their argument hashes as objects mimicking
      # Nodes, Issues, etc
      allow(@content_service).to receive(:create_node) do |args|
        obj = OpenStruct.new(args)
        obj.define_singleton_method(:set_property) { |_, __| }
        obj
      end
      allow(@content_service).to receive(:create_issue) do |args|
        OpenStruct.new(args)
      end
      allow(@content_service).to receive(:create_evidence) do |args|
        OpenStruct.new(args)
      end
    end

    it 'creates nodes, issues, and evidence as needed' do
      # Host node
      #
      # create_node should be called once for each issue in the xml,
      # but ContentService knows it's already created and NOOPs
      expect(@content_service).to receive(:create_node)
      .with(hash_including label: 'github.com/dradis/dradis-burp')
      .exactly(1).times

      # # create_issue should be called once for each issue in the xml
      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include("Strict transport security not enforced")
        expect(args[:text]).to include('*application*', '@Wi-Fi@')
        expect(args[:id]).to eq(16777984)
        OpenStruct.new(args)
      end.once
      
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include('Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
        expect(args[:content]).to include("http://1.1.1.1/dradis/sessions")
        expect(args[:issue].text).to include("Strict transport security not enforced")
        expect(args[:issue].text).to include('*application*', '@Wi-Fi@')
        expect(args[:node].label).to eq('github.com/dradis/dradis-burp')
      end.once

      # Run the import
      @importer.import(file: 'spec/fixtures/files/burp.html')
    end
  end
end
