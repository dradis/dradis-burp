require 'spec_helper'
require 'ostruct'

module Dradis::Plugins
  describe 'Burp upload plugin' do
    before(:each) do
      # Stub template service
      templates_dir = File.expand_path('../../templates', __FILE__)
      expect_any_instance_of(TemplateService)
      .to receive(:default_templates_dir).and_return(templates_dir)

      # Init services
      plugin = Dradis::Plugins::Burp

      @content_service = Dradis::Plugins::ContentService::Base.new(
        logger: Logger.new(STDOUT),
        plugin: plugin
      )

      @importer = Dradis::Plugins::Burp::Importer.new(
        content_service: @content_service
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

    it "creates nodes, issues, and evidence as needed" do

      # Host node
      #
      # create_node should be called once for each issue in the xml,
      # but ContentService knows it's already created and NOOPs
      expect(@content_service).to receive(:create_node)
      .with(hash_including label: '10.0.0.1')
      .exactly(4).times

      # create_issue should be called once for each issue in the xml
      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include("#[Title]#\nIssue 1")
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("Lorem ipsum dolor sit amet")
        expect(args[:issue].text).to include("#[Title]#\nIssue 1")
        expect(args[:node].label).to eq("10.0.0.1")
      end.once

      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include("#[Title]#\nIssue 2")
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("Lorem ipsum dolor sit amet")
        expect(args[:issue].text).to include("#[Title]#\nIssue 2")
        expect(args[:node].label).to eq("10.0.0.1")
      end.once

      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include("#[Title]#\nIssue 3")
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("Lorem ipsum dolor sit amet")
        expect(args[:issue].text).to include("#[Title]#\nIssue 3")
        expect(args[:node].label).to eq("10.0.0.1")
      end.once

      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include("#[Title]#\nIssue 4")
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("Lorem ipsum dolor sit amet")
        expect(args[:issue].text).to include("#[Title]#\nIssue 4")
        expect(args[:node].label).to eq("10.0.0.1")
      end.once


      # Run the import
      @importer.import(file: 'spec/fixtures/files/burp.xml')
    end

  end
end
