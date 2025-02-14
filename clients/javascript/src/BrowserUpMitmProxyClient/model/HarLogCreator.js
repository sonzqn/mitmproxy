/**
 * BrowserUp MitmProxy
 * ___ This is the REST API for controlling the BrowserUp MitmProxy. The BrowserUp MitmProxy is a swiss army knife for automated testing that captures HTTP traffic in HAR files. It is also useful for Selenium/Cypress tests. ___ 
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

/**
 * The HarLogCreator model module.
 * @module BrowserUpMitmProxyClient/model/HarLogCreator
 * @version 1.0.0
 */
class HarLogCreator {
    /**
     * Constructs a new <code>HarLogCreator</code>.
     * @alias module:BrowserUpMitmProxyClient/model/HarLogCreator
     * @param name {String} 
     * @param version {String} 
     */
    constructor(name, version) { 
        
        HarLogCreator.initialize(this, name, version);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj, name, version) { 
        obj['name'] = name;
        obj['version'] = version;
    }

    /**
     * Constructs a <code>HarLogCreator</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:BrowserUpMitmProxyClient/model/HarLogCreator} obj Optional instance to populate.
     * @return {module:BrowserUpMitmProxyClient/model/HarLogCreator} The populated <code>HarLogCreator</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new HarLogCreator();

            if (data.hasOwnProperty('name')) {
                obj['name'] = ApiClient.convertToType(data['name'], 'String');
            }
            if (data.hasOwnProperty('version')) {
                obj['version'] = ApiClient.convertToType(data['version'], 'String');
            }
            if (data.hasOwnProperty('comment')) {
                obj['comment'] = ApiClient.convertToType(data['comment'], 'String');
            }
        }
        return obj;
    }


}

/**
 * @member {String} name
 */
HarLogCreator.prototype['name'] = undefined;

/**
 * @member {String} version
 */
HarLogCreator.prototype['version'] = undefined;

/**
 * @member {String} comment
 */
HarLogCreator.prototype['comment'] = undefined;






export default HarLogCreator;

