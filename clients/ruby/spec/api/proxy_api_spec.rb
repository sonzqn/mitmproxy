=begin
#BrowserUp Proxy

#BrowserUp Proxy Control API

The version of the OpenAPI document: 1.0.0

Generated by: https://openapi-generator.tech
OpenAPI Generator version: 5.0.1

=end

require 'spec_helper'
require 'json'

# Unit tests for BrowserupProxyClient::ProxyApi
# Automatically generated by openapi-generator (https://openapi-generator.tech)
# Please update as you see appropriate
describe 'ProxyApi' do
  before do
    # run before each test
    @api_instance = BrowserupProxyClient::ProxyApi.new
  end

  after do
    # run after each test
  end

  describe 'test an instance of ProxyApi' do
    it 'should create an instance of ProxyApi' do
      expect(@api_instance).to be_instance_of(BrowserupProxyClient::ProxyApi)
    end
  end

  # unit tests for allowlist_delete
  # Deletes the AllowList, which will turn-off allowlist based filtering
  # @param [Hash] opts the optional parameters
  # @return [nil]
  describe 'allowlist_delete test' do
    it 'should work' do
      # assertion here. ref: https://www.relishapp.com/rspec/rspec-expectations/docs/built-in-matchers
    end
  end

  # unit tests for allowlist_get
  # Get an AllowList
  # @param [Hash] opts the optional parameters
  # @return [AllowList]
  describe 'allowlist_get test' do
    it 'should work' do
      # assertion here. ref: https://www.relishapp.com/rspec/rspec-expectations/docs/built-in-matchers
    end
  end

  # unit tests for allowlist_post
  # Sets an AllowList
  # @param [Hash] opts the optional parameters
  # @option opts [AllowList] :allow_list 
  # @return [nil]
  describe 'allowlist_post test' do
    it 'should work' do
      # assertion here. ref: https://www.relishapp.com/rspec/rspec-expectations/docs/built-in-matchers
    end
  end

  # unit tests for blocklist_get
  # Get a blocklist
  # @param [Hash] opts the optional parameters
  # @return [BlockList]
  describe 'blocklist_get test' do
    it 'should work' do
      # assertion here. ref: https://www.relishapp.com/rspec/rspec-expectations/docs/built-in-matchers
    end
  end

  # unit tests for blocklist_post
  # Sets an BlockList
  # @param [Hash] opts the optional parameters
  # @option opts [BlockList] :block_list 
  # @return [nil]
  describe 'blocklist_post test' do
    it 'should work' do
      # assertion here. ref: https://www.relishapp.com/rspec/rspec-expectations/docs/built-in-matchers
    end
  end

end
