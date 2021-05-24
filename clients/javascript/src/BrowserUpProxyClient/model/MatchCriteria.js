/**
 * BrowserUp Proxy
 * ___ This is the REST API for controlling the BrowserUp Proxy. The BrowserUp Proxy is a swiss army knife for automated testing that captures HTTP traffic in HAR files. It is also useful for Selenium/Cypress tests. ___ 
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
import NameValuePair from './NameValuePair';

/**
 * The MatchCriteria model module.
 * @module BrowserUpProxyClient/model/MatchCriteria
 * @version 1.0.0
 */
class MatchCriteria {
    /**
     * Constructs a new <code>MatchCriteria</code>.
     * A set of criteria for filtering HTTP Requests and Responses.                          Criteria are AND based, and use python regular expressions for string comparison
     * @alias module:BrowserUpProxyClient/model/MatchCriteria
     */
    constructor() { 
        
        MatchCriteria.initialize(this);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj) { 
    }

    /**
     * Constructs a <code>MatchCriteria</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:BrowserUpProxyClient/model/MatchCriteria} obj Optional instance to populate.
     * @return {module:BrowserUpProxyClient/model/MatchCriteria} The populated <code>MatchCriteria</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new MatchCriteria();

            if (data.hasOwnProperty('url')) {
                obj['url'] = ApiClient.convertToType(data['url'], 'String');
            }
            if (data.hasOwnProperty('page')) {
                obj['page'] = ApiClient.convertToType(data['page'], 'String');
            }
            if (data.hasOwnProperty('status')) {
                obj['status'] = ApiClient.convertToType(data['status'], 'String');
            }
            if (data.hasOwnProperty('content')) {
                obj['content'] = ApiClient.convertToType(data['content'], 'String');
            }
            if (data.hasOwnProperty('content_type')) {
                obj['content_type'] = ApiClient.convertToType(data['content_type'], 'String');
            }
            if (data.hasOwnProperty('websocket_message')) {
                obj['websocket_message'] = ApiClient.convertToType(data['websocket_message'], 'String');
            }
            if (data.hasOwnProperty('request_header')) {
                obj['request_header'] = ApiClient.convertToType(data['request_header'], NameValuePair);
            }
            if (data.hasOwnProperty('request_cookie')) {
                obj['request_cookie'] = ApiClient.convertToType(data['request_cookie'], NameValuePair);
            }
            if (data.hasOwnProperty('response_header')) {
                obj['response_header'] = ApiClient.convertToType(data['response_header'], NameValuePair);
            }
            if (data.hasOwnProperty('response_cookie')) {
                obj['response_cookie'] = ApiClient.convertToType(data['response_cookie'], NameValuePair);
            }
            if (data.hasOwnProperty('json_valid')) {
                obj['json_valid'] = ApiClient.convertToType(data['json_valid'], 'Boolean');
            }
            if (data.hasOwnProperty('json_path')) {
                obj['json_path'] = ApiClient.convertToType(data['json_path'], 'String');
            }
            if (data.hasOwnProperty('json_schema')) {
                obj['json_schema'] = ApiClient.convertToType(data['json_schema'], 'String');
            }
        }
        return obj;
    }


}

/**
 * Request URL regexp to match
 * @member {String} url
 */
MatchCriteria.prototype['url'] = undefined;

/**
 * current|all
 * @member {String} page
 */
MatchCriteria.prototype['page'] = undefined;

/**
 * HTTP Status code to match.
 * @member {String} status
 */
MatchCriteria.prototype['status'] = undefined;

/**
 * Body content regexp content to match
 * @member {String} content
 */
MatchCriteria.prototype['content'] = undefined;

/**
 * Content type
 * @member {String} content_type
 */
MatchCriteria.prototype['content_type'] = undefined;

/**
 * Websocket message text to match
 * @member {String} websocket_message
 */
MatchCriteria.prototype['websocket_message'] = undefined;

/**
 * @member {module:BrowserUpProxyClient/model/NameValuePair} request_header
 */
MatchCriteria.prototype['request_header'] = undefined;

/**
 * @member {module:BrowserUpProxyClient/model/NameValuePair} request_cookie
 */
MatchCriteria.prototype['request_cookie'] = undefined;

/**
 * @member {module:BrowserUpProxyClient/model/NameValuePair} response_header
 */
MatchCriteria.prototype['response_header'] = undefined;

/**
 * @member {module:BrowserUpProxyClient/model/NameValuePair} response_cookie
 */
MatchCriteria.prototype['response_cookie'] = undefined;

/**
 * Is valid JSON
 * @member {Boolean} json_valid
 */
MatchCriteria.prototype['json_valid'] = undefined;

/**
 * Has JSON path
 * @member {String} json_path
 */
MatchCriteria.prototype['json_path'] = undefined;

/**
 * Validates against passed JSON schema
 * @member {String} json_schema
 */
MatchCriteria.prototype['json_schema'] = undefined;






export default MatchCriteria;

