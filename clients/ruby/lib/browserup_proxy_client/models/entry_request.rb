=begin
#BrowserUp MitmProxy

#___ This is the REST API for controlling the BrowserUp MitmProxy. The BrowserUp MitmProxy is a swiss army knife for automated testing that captures HTTP traffic in HAR files. It is also useful for Selenium/Cypress tests. ___ 

The version of the OpenAPI document: 1.0.0

Generated by: https://openapi-generator.tech
OpenAPI Generator version: 5.2.0

=end

require 'date'
require 'time'

module BrowserupProxy
  class EntryRequest
    attr_accessor :method

    attr_accessor :url

    attr_accessor :http_version

    attr_accessor :cookies

    attr_accessor :headers

    attr_accessor :query_string

    # Posted data info.
    attr_accessor :post_data

    attr_accessor :headers_size

    attr_accessor :body_size

    attr_accessor :comment

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        :'method' => :'method',
        :'url' => :'url',
        :'http_version' => :'httpVersion',
        :'cookies' => :'cookies',
        :'headers' => :'headers',
        :'query_string' => :'queryString',
        :'post_data' => :'postData',
        :'headers_size' => :'headersSize',
        :'body_size' => :'bodySize',
        :'comment' => :'comment'
      }
    end

    # Returns all the JSON keys this model knows about
    def self.acceptable_attributes
      attribute_map.values
    end

    # Attribute type mapping.
    def self.openapi_types
      {
        :'method' => :'String',
        :'url' => :'String',
        :'http_version' => :'String',
        :'cookies' => :'Array<EntryRequestCookies>',
        :'headers' => :'Array<Header>',
        :'query_string' => :'Array<EntryRequestQueryString>',
        :'post_data' => :'Object',
        :'headers_size' => :'Integer',
        :'body_size' => :'Integer',
        :'comment' => :'String'
      }
    end

    # List of attributes with nullable: true
    def self.openapi_nullable
      Set.new([
      ])
    end

    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    def initialize(attributes = {})
      if (!attributes.is_a?(Hash))
        fail ArgumentError, "The input argument (attributes) must be a hash in `BrowserupProxy::EntryRequest` initialize method"
      end

      # check to see if the attribute exists and convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h|
        if (!self.class.attribute_map.key?(k.to_sym))
          fail ArgumentError, "`#{k}` is not a valid attribute in `BrowserupProxy::EntryRequest`. Please check the name to make sure it's valid. List of attributes: " + self.class.attribute_map.keys.inspect
        end
        h[k.to_sym] = v
      }

      if attributes.key?(:'method')
        self.method = attributes[:'method']
      end

      if attributes.key?(:'url')
        self.url = attributes[:'url']
      end

      if attributes.key?(:'http_version')
        self.http_version = attributes[:'http_version']
      end

      if attributes.key?(:'cookies')
        if (value = attributes[:'cookies']).is_a?(Array)
          self.cookies = value
        end
      end

      if attributes.key?(:'headers')
        if (value = attributes[:'headers']).is_a?(Array)
          self.headers = value
        end
      end

      if attributes.key?(:'query_string')
        if (value = attributes[:'query_string']).is_a?(Array)
          self.query_string = value
        end
      end

      if attributes.key?(:'post_data')
        self.post_data = attributes[:'post_data']
      end

      if attributes.key?(:'headers_size')
        self.headers_size = attributes[:'headers_size']
      end

      if attributes.key?(:'body_size')
        self.body_size = attributes[:'body_size']
      end

      if attributes.key?(:'comment')
        self.comment = attributes[:'comment']
      end
    end

    # Show invalid properties with the reasons. Usually used together with valid?
    # @return Array for valid properties with the reasons
    def list_invalid_properties
      invalid_properties = Array.new
      if @method.nil?
        invalid_properties.push('invalid value for "method", method cannot be nil.')
      end

      if @url.nil?
        invalid_properties.push('invalid value for "url", url cannot be nil.')
      end

      if @http_version.nil?
        invalid_properties.push('invalid value for "http_version", http_version cannot be nil.')
      end

      if @cookies.nil?
        invalid_properties.push('invalid value for "cookies", cookies cannot be nil.')
      end

      if @headers.nil?
        invalid_properties.push('invalid value for "headers", headers cannot be nil.')
      end

      if @query_string.nil?
        invalid_properties.push('invalid value for "query_string", query_string cannot be nil.')
      end

      if @headers_size.nil?
        invalid_properties.push('invalid value for "headers_size", headers_size cannot be nil.')
      end

      if @body_size.nil?
        invalid_properties.push('invalid value for "body_size", body_size cannot be nil.')
      end

      invalid_properties
    end

    # Check to see if the all the properties in the model are valid
    # @return true if the model is valid
    def valid?
      return false if @method.nil?
      return false if @url.nil?
      return false if @http_version.nil?
      return false if @cookies.nil?
      return false if @headers.nil?
      return false if @query_string.nil?
      return false if @headers_size.nil?
      return false if @body_size.nil?
      true
    end

    # Checks equality by comparing each attribute.
    # @param [Object] Object to be compared
    def ==(o)
      return true if self.equal?(o)
      self.class == o.class &&
          method == o.method &&
          url == o.url &&
          http_version == o.http_version &&
          cookies == o.cookies &&
          headers == o.headers &&
          query_string == o.query_string &&
          post_data == o.post_data &&
          headers_size == o.headers_size &&
          body_size == o.body_size &&
          comment == o.comment
    end

    # @see the `==` method
    # @param [Object] Object to be compared
    def eql?(o)
      self == o
    end

    # Calculates hash code according to all attributes.
    # @return [Integer] Hash code
    def hash
      [method, url, http_version, cookies, headers, query_string, post_data, headers_size, body_size, comment].hash
    end

    # Builds the object from hash
    # @param [Hash] attributes Model attributes in the form of hash
    # @return [Object] Returns the model itself
    def self.build_from_hash(attributes)
      new.build_from_hash(attributes)
    end

    # Builds the object from hash
    # @param [Hash] attributes Model attributes in the form of hash
    # @return [Object] Returns the model itself
    def build_from_hash(attributes)
      return nil unless attributes.is_a?(Hash)
      self.class.openapi_types.each_pair do |key, type|
        if attributes[self.class.attribute_map[key]].nil? && self.class.openapi_nullable.include?(key)
          self.send("#{key}=", nil)
        elsif type =~ /\AArray<(.*)>/i
          # check to ensure the input is an array given that the attribute
          # is documented as an array but the input is not
          if attributes[self.class.attribute_map[key]].is_a?(Array)
            self.send("#{key}=", attributes[self.class.attribute_map[key]].map { |v| _deserialize($1, v) })
          end
        elsif !attributes[self.class.attribute_map[key]].nil?
          self.send("#{key}=", _deserialize(type, attributes[self.class.attribute_map[key]]))
        end
      end

      self
    end

    # Deserializes the data based on type
    # @param string type Data type
    # @param string value Value to be deserialized
    # @return [Object] Deserialized data
    def _deserialize(type, value)
      case type.to_sym
      when :Time
        Time.parse(value)
      when :Date
        Date.parse(value)
      when :String
        value.to_s
      when :Integer
        value.to_i
      when :Float
        value.to_f
      when :Boolean
        if value.to_s =~ /\A(true|t|yes|y|1)\z/i
          true
        else
          false
        end
      when :Object
        # generic object (usually a Hash), return directly
        value
      when /\AArray<(?<inner_type>.+)>\z/
        inner_type = Regexp.last_match[:inner_type]
        value.map { |v| _deserialize(inner_type, v) }
      when /\AHash<(?<k_type>.+?), (?<v_type>.+)>\z/
        k_type = Regexp.last_match[:k_type]
        v_type = Regexp.last_match[:v_type]
        {}.tap do |hash|
          value.each do |k, v|
            hash[_deserialize(k_type, k)] = _deserialize(v_type, v)
          end
        end
      else # model
        # models (e.g. Pet) or oneOf
        klass = BrowserupProxy.const_get(type)
        klass.respond_to?(:openapi_one_of) ? klass.build(value) : klass.build_from_hash(value)
      end
    end

    # Returns the string representation of the object
    # @return [String] String presentation of the object
    def to_s
      to_hash.to_s
    end

    # to_body is an alias to to_hash (backward compatibility)
    # @return [Hash] Returns the object in the form of hash
    def to_body
      to_hash
    end

    # Returns the object in the form of hash
    # @return [Hash] Returns the object in the form of hash
    def to_hash
      hash = {}
      self.class.attribute_map.each_pair do |attr, param|
        value = self.send(attr)
        if value.nil?
          is_nullable = self.class.openapi_nullable.include?(attr)
          next if !is_nullable || (is_nullable && !instance_variable_defined?(:"@#{attr}"))
        end

        hash[param] = _to_hash(value)
      end
      hash
    end

    # Outputs non-array value in the form of hash
    # For object, use to_hash. Otherwise, just return the value
    # @param [Object] value Any valid value
    # @return [Hash] Returns the value in the form of hash
    def _to_hash(value)
      if value.is_a?(Array)
        value.compact.map { |v| _to_hash(v) }
      elsif value.is_a?(Hash)
        {}.tap do |hash|
          value.each { |k, v| hash[k] = _to_hash(v) }
        end
      elsif value.respond_to? :to_hash
        value.to_hash
      else
        value
      end
    end

  end

end
