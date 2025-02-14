=begin
#BrowserUp Proxy

#___ This is the REST API for controlling the BrowserUp Proxy.  The BrowserUp Proxy is a swiss army knife for automated testing that captures HTTP traffic in HAR files. It is also useful for Selenium/Cypress tests. ___ 

The version of the OpenAPI document: 1.0.0

Generated by: https://openapi-generator.tech
OpenAPI Generator version: 5.1.1

=end

# Common files
require 'browserup_proxy_client/api_client'
require 'browserup_proxy_client/api_error'
require 'browserup_proxy_client/version'
require 'browserup_proxy_client/configuration'

# Models
require 'browserup_proxy_client/models/entry'
require 'browserup_proxy_client/models/entry_request'
require 'browserup_proxy_client/models/entry_request_cookies'
require 'browserup_proxy_client/models/entry_request_query_string'
require 'browserup_proxy_client/models/entry_response'
require 'browserup_proxy_client/models/entry_response_content'
require 'browserup_proxy_client/models/har'
require 'browserup_proxy_client/models/har_log'
require 'browserup_proxy_client/models/har_log_creator'
require 'browserup_proxy_client/models/header'
require 'browserup_proxy_client/models/match_criteria'
require 'browserup_proxy_client/models/name_value_pair'
require 'browserup_proxy_client/models/page'
require 'browserup_proxy_client/models/page_page_timings'
require 'browserup_proxy_client/models/verify_result'

# APIs
require 'browserup_proxy_client/api/browser_up_proxy_api'

module BrowserupProxy
  class << self
    # Customize default settings for the SDK using block.
    #   BrowserupProxy.configure do |config|
    #     config.username = "xxx"
    #     config.password = "xxx"
    #   end
    # If no block given, return the default Configuration object.
    def configure
      if block_given?
        yield(Configuration.default)
      else
        Configuration.default
      end
    end
  end
end
