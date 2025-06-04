require 'spec_helper'
require 'ostruct'

describe 'Burp upload plugin' do
  describe Burp::Xml::Issue do
    it 'handles invalid utf-8 bytes' do
      doc = Nokogiri::XML(File.read('spec/fixtures/files/invalid-utf-issue.xml'))
      xml_issue = doc.xpath('issues/issue').first
      issue = Burp::Xml::Issue.new(xml_issue)

      expect { issue.request.encode('utf-8') }.to_not raise_error
    end
  end

  describe Dradis::Plugins::Burp::Xml::Importer do
    before(:each) do
      # Stub mappings service
      allow(Dradis::Plugins::MappingService).to receive(:new).and_return(
        StubbedMappingService.new
      )

      # Init services
      plugin = Dradis::Plugins::Burp::Xml

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
      .with(hash_including label: '10.0.0.1')
      .exactly(4).times

      # create_issue should be called once for each issue in the xml
      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include("Issue 1")
        expect(args[:id]).to eq(8781630)
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include('Lorem ipsum dolor sit amet')
        expect(args[:issue].text).to include("Issue 1")
        expect(args[:node].label).to eq('10.0.0.1')
      end.once

      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include("Issue 2")
        expect(args[:id]).to eq(8781631)
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include('Lorem ipsum dolor sit amet')
        expect(args[:issue].text).to include("Issue 2")
        expect(args[:node].label).to eq('10.0.0.1')
      end.once

      # Issue 3 is an Extension finding so we need to confirm
      # that it triggers process_extension_issues instead of process_burp_issues
      # and the plugin_id is not set to the Type (134217728)
      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include("Issue 3")
        expect(args[:id]).to eq('Issue3')
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include('Lorem ipsum dolor sit amet')
        expect(args[:issue].text).to include("Issue 3")
        expect(args[:node].label).to eq('10.0.0.1')
      end.once

      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include("Issue 4")
        expect(args[:id]).to eq(8781633)
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include('Lorem ipsum dolor sit amet')
        expect(args[:issue].text).to include("Issue 4")
        expect(args[:node].label).to eq('10.0.0.1')
      end.once

      # Run the import
      @importer.import(file: 'spec/fixtures/files/burp.xml')
    end

    it 'returns the highest <severity> at the Issue level' do
      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:id]).to eq(8781630)
        expect(args[:text]).to include("Issue 1")
        expect(args[:text]).to include("Information")
        OpenStruct.new(args)
      end

      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("Information")
        expect(args[:issue].text).to include("Issue 1")
        expect(args[:node].label).to eq('10.0.0.1')
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("High")
        expect(args[:issue].text).to include("Issue 2")
        expect(args[:node].label).to eq('10.0.0.1')
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("Medium")
        expect(args[:issue].text).to include("Issue 3")
        expect(args[:node].label).to eq('10.0.0.1')
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("High")
        expect(args[:issue].text).to include("Issue 4")
        expect(args[:node].label).to eq('10.0.0.1')
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("Low")
        expect(args[:content]).to include("test multiple request")
        expect(args[:content]).to include("test multiple response")
        expect(args[:issue].text).to include("Issue 5")
        expect(args[:node].label).to eq('10.0.0.1')
      end.once

      # Run the import
      @importer.import(file: 'spec/fixtures/files/burp_issue_severity.xml')
    end
  end
end
