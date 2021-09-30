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
 * The Counter model module.
 * @module BrowserUpMitmProxyClient/model/Counter
 * @version 1.0.0
 */
class Counter {
    /**
     * Constructs a new <code>Counter</code>.
     * @alias module:BrowserUpMitmProxyClient/model/Counter
     * @param value {Number} Value for the counter
     * @param name {String} Name of Custom Counter value you are adding to the page under _counters
     */
    constructor(value, name) { 
        
        Counter.initialize(this, value, name);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj, value, name) { 
        obj['value'] = value;
        obj['name'] = name;
    }

    /**
     * Constructs a <code>Counter</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:BrowserUpMitmProxyClient/model/Counter} obj Optional instance to populate.
     * @return {module:BrowserUpMitmProxyClient/model/Counter} The populated <code>Counter</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new Counter();

            if (data.hasOwnProperty('value')) {
                obj['value'] = ApiClient.convertToType(data['value'], 'Number');
            }
            if (data.hasOwnProperty('name')) {
                obj['name'] = ApiClient.convertToType(data['name'], 'String');
            }
        }
        return obj;
    }


}

/**
 * Value for the counter
 * @member {Number} value
 */
Counter.prototype['value'] = undefined;

/**
 * Name of Custom Counter value you are adding to the page under _counters
 * @member {String} name
 */
Counter.prototype['name'] = undefined;






export default Counter;

