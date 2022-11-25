require 'spec_helper'
require 'ostruct'

describe 'Burp upload plugin' do

  describe Burp::Xml::Issue do
    it 'handles invalid utf-8 bytes' do
      doc = Nokogiri::XML(File.read('spec/fixtures/files/invalid-utf-issue.xml'))
      xml_issue = doc.xpath('issues/issue').first
      issue = Burp::Xml::Issue.new(xml_issue)

      expect{ issue.request.encode('utf-8') }.to_not raise_error
    end
  end

  describe  Dradis::Plugins::Burp::Xml::Importer do
    before(:each) do
      # Stub template service
      templates_dir = File.expand_path('../../templates', __FILE__)
      expect_any_instance_of(Dradis::Plugins::TemplateService)
      .to receive(:default_templates_dir).and_return(templates_dir)

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
        expect(args[:text]).to include("#[Title]#\nIssue 1")
        expect(args[:id]).to eq(8781630)
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("Lorem ipsum dolor sit amet")
        expect(args[:issue].text).to include("#[Title]#\nIssue 1")
        expect(args[:node].label).to eq("10.0.0.1")
      end.once

      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include("#[Title]#\nIssue 2")
        expect(args[:id]).to eq(8781631)
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("Lorem ipsum dolor sit amet")
        expect(args[:issue].text).to include("#[Title]#\nIssue 2")
        expect(args[:node].label).to eq("10.0.0.1")
      end.once

      # Issue 3 is an Extension finding so we need to confirm
      # that it triggers process_extension_issues instead of process_burp_issues
      # and the plugin_id is not set to the Type (134217728)
      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include("#[Title]#\nIssue 3")
        expect(args[:id]).to eq("Issue3")
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("Lorem ipsum dolor sit amet")
        expect(args[:issue].text).to include("#[Title]#\nIssue 3")
        expect(args[:node].label).to eq("10.0.0.1")
      end.once

      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include("#[Title]#\nIssue 4")
        expect(args[:id]).to eq(8781633)
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

    it 'returns the highest <severity> at the Issue level' do

      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:id]).to eq(8781630)
        expect(args[:text]).to include("#[Title]#\nIssue 1")
        expect(args[:text]).to include("#[Severity]#\nInformation")
        OpenStruct.new(args)
      end

      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("#[Severity]#\nInformation")
        expect(args[:issue].text).to include("#[Title]#\nIssue 1")
        expect(args[:node].label).to eq('10.0.0.1')
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("#[Severity]#\nHigh")
        expect(args[:issue].text).to include("#[Title]#\nIssue 2")
        expect(args[:node].label).to eq('10.0.0.1')
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("#[Severity]#\nMedium")
        expect(args[:issue].text).to include("#[Title]#\nIssue 3")
        expect(args[:node].label).to eq('10.0.0.1')
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("#[Severity]#\nHigh")
        expect(args[:issue].text).to include("#[Title]#\nIssue 4")
        expect(args[:node].label).to eq('10.0.0.1')
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("#[Severity]#\nLow")
        expect(args[:issue].text).to include("#[Title]#\nIssue 5")
        expect(args[:node].label).to eq('10.0.0.1')
      end.once

      # Run the import
      @importer.import(file: 'spec/fixtures/files/burp_issue_severity.xml')
    end
  end

  describe  Dradis::Plugins::Burp::Html::Importer do
    before(:each) do
      # Stub template service
      templates_dir = File.expand_path('../../templates', __FILE__)
      expect_any_instance_of(Dradis::Plugins::TemplateService)
      .to receive(:default_templates_dir).and_return(templates_dir)

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

    it "creates nodes, issues, and evidence as needed" do

      # Host node
      #
      # create_node should be called once for each issue in the xml,
      # but ContentService knows it's already created and NOOPs
      expect(@content_service).to receive(:create_node)
      .with(hash_including label: 'github.com/dradis/dradis-burp')
      .exactly(1).times

      # # create_issue should be called once for each issue in the xml
      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include("#[Title]#\nStrict transport security not enforced")
        expect(args[:text]).to include("*application*", "@Wi-Fi@")
        expect(args[:id]).to eq(16777984)
        OpenStruct.new(args)
      end.once
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        expect(args[:content]).to include("#[Location]#\nhttp://1.1.1.1/dradis/sessions")
        expect(args[:issue].text).to include("#[Title]#\nStrict transport security not enforced")
        expect(args[:issue].text).to include("*application*", "@Wi-Fi@")
        expect(args[:node].label).to eq("github.com/dradis/dradis-burp")
      end.once

      # Run the import
      @importer.import(file: 'spec/fixtures/files/burp.html')
    end

  end
end
