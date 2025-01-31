/**
 * BrowserUp Proxy
 * ___ This is the REST API for controlling the BrowserUp Proxy.  The BrowserUp Proxy is a swiss army knife for automated testing. It allows traffic capture in HAR files and manipulation.  It is also useful for Selenium/Cypress tests. ___ 
 *
 * The version of the OpenAPI document: 1.0.0
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 *
 */

import ApiClient from '../ApiClient';
import EntryRequestCookies from './EntryRequestCookies';
import EntryRequestQueryString from './EntryRequestQueryString';
import Header from './Header';

/**
 * The EntryRequest model module.
 * @module BrowserUpProxyClient/model/EntryRequest
 * @version 1.0.0
 */
class EntryRequest {
    /**
     * Constructs a new <code>EntryRequest</code>.
     * @alias module:BrowserUpProxyClient/model/EntryRequest
     * @param method {String} 
     * @param url {String} 
     * @param httpVersion {String} 
     * @param cookies {Array.<module:BrowserUpProxyClient/model/EntryRequestCookies>} 
     * @param headers {Array.<module:BrowserUpProxyClient/model/Header>} 
     * @param queryString {Array.<module:BrowserUpProxyClient/model/EntryRequestQueryString>} 
     * @param headersSize {Number} 
     * @param bodySize {Number} 
     */
    constructor(method, url, httpVersion, cookies, headers, queryString, headersSize, bodySize) { 
        
        EntryRequest.initialize(this, method, url, httpVersion, cookies, headers, queryString, headersSize, bodySize);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj, method, url, httpVersion, cookies, headers, queryString, headersSize, bodySize) { 
        obj['method'] = method;
        obj['url'] = url;
        obj['httpVersion'] = httpVersion;
        obj['cookies'] = cookies;
        obj['headers'] = headers;
        obj['queryString'] = queryString;
        obj['headersSize'] = headersSize;
        obj['bodySize'] = bodySize;
    }

    /**
     * Constructs a <code>EntryRequest</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:BrowserUpProxyClient/model/EntryRequest} obj Optional instance to populate.
     * @return {module:BrowserUpProxyClient/model/EntryRequest} The populated <code>EntryRequest</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new EntryRequest();

            if (data.hasOwnProperty('method')) {
                obj['method'] = ApiClient.convertToType(data['method'], 'String');
            }
            if (data.hasOwnProperty('url')) {
                obj['url'] = ApiClient.convertToType(data['url'], 'String');
            }
            if (data.hasOwnProperty('httpVersion')) {
                obj['httpVersion'] = ApiClient.convertToType(data['httpVersion'], 'String');
            }
            if (data.hasOwnProperty('cookies')) {
                obj['cookies'] = ApiClient.convertToType(data['cookies'], [EntryRequestCookies]);
            }
            if (data.hasOwnProperty('headers')) {
                obj['headers'] = ApiClient.convertToType(data['headers'], [Header]);
            }
            if (data.hasOwnProperty('queryString')) {
                obj['queryString'] = ApiClient.convertToType(data['queryString'], [EntryRequestQueryString]);
            }
            if (data.hasOwnProperty('postData')) {
                obj['postData'] = ApiClient.convertToType(data['postData'], Object);
            }
            if (data.hasOwnProperty('headersSize')) {
                obj['headersSize'] = ApiClient.convertToType(data['headersSize'], 'Number');
            }
            if (data.hasOwnProperty('bodySize')) {
                obj['bodySize'] = ApiClient.convertToType(data['bodySize'], 'Number');
            }
            if (data.hasOwnProperty('comment')) {
                obj['comment'] = ApiClient.convertToType(data['comment'], 'String');
            }
        }
        return obj;
    }


}

/**
 * @member {String} method
 */
EntryRequest.prototype['method'] = undefined;

/**
 * @member {String} url
 */
EntryRequest.prototype['url'] = undefined;

/**
 * @member {String} httpVersion
 */
EntryRequest.prototype['httpVersion'] = undefined;

/**
 * @member {Array.<module:BrowserUpProxyClient/model/EntryRequestCookies>} cookies
 */
EntryRequest.prototype['cookies'] = undefined;

/**
 * @member {Array.<module:BrowserUpProxyClient/model/Header>} headers
 */
EntryRequest.prototype['headers'] = undefined;

/**
 * @member {Array.<module:BrowserUpProxyClient/model/EntryRequestQueryString>} queryString
 */
EntryRequest.prototype['queryString'] = undefined;

/**
 * Posted data info.
 * @member {Object} postData
 */
EntryRequest.prototype['postData'] = undefined;

/**
 * @member {Number} headersSize
 */
EntryRequest.prototype['headersSize'] = undefined;

/**
 * @member {Number} bodySize
 */
EntryRequest.prototype['bodySize'] = undefined;

/**
 * @member {String} comment
 */
EntryRequest.prototype['comment'] = undefined;






export default EntryRequest;

