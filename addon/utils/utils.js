import { typeOf } from '@ember/utils';
import { deprecate } from '@ember/application/deprecations';

/**
 * This takes a hash of attributes or a list of CognitoUserAttributes list,
 * and returns a hash. It also deprecates the CognitoUserAttributes path.
 *
 * @param attributes
 */
export function normalizeAttributes(attributes, showDeprecation = true) {
  // If the attributeList is an object, then it is treated as
  // a hash of attributes, otherwise it is treated as a list of CognitoUserAttributes,
  // for backward compatibility.
  if (typeOf(attributes) === 'array') {
    deprecate(
      'You can pass a hash to this function rather than a list of CognitoUserAttribute objects.',
      !showDeprecation,
      { id: 'ember-cognito-attribute-list', until: '1.0' }
    );
    // TODO: Deprecate this path.
    let newAttrs = {};
    for (const attr of attributes) {
      newAttrs[attr.getName()] = attr.getValue();
    }
    attributes = newAttrs;
  }
  return attributes;
}
