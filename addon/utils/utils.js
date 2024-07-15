import { typeOf } from '@ember/utils';
import { deprecate } from '@ember/debug';

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
      {
        for: 'ember-cognito',
        id: 'ember-cognito-attribute-list',
        since: '0.12.0',
        until: '1.0.0',
      }
    );
    let newAttrs = {};
    for (const attr of attributes) {
      newAttrs[attr.getName()] = attr.getValue();
    }
    attributes = newAttrs;
  }
  return attributes;
}

/**
 * The possible values of nextStep in signUp/signIn flows
 *
 * @param attributes
 */
export const CognitoNextSteps = Object.freeze({
  CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED: "CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED", // The user was created with a temporary password and must set a new one. Complete the process with confirmSignIn.
  CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE: "CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE", // The sign-in must be confirmed with a custom challenge response. Complete the process with confirmSignIn.
  CONFIRM_SIGN_IN_WITH_TOTP_CODE: "CONFIRM_SIGN_IN_WITH_TOTP_CODE", // The sign-in must be confirmed with a TOTP code from the user. Complete the process with confirmSignIn.
  CONTINUE_SIGN_IN_WITH_TOTP_SETUP: "CONTINUE_SIGN_IN_WITH_TOTP_SETUP", // The TOTP setup process must be continued. Complete the process with confirmSignIn. -- If this MFA method is required but not set up.
  CONFIRM_SIGN_IN_WITH_SMS_CODE: "CONFIRM_SIGN_IN_WITH_SMS_CODE", // The sign-in must be confirmed with a SMS code from the user. Complete the process with confirmSignIn.
  CONTINUE_SIGN_IN_WITH_MFA_SELECTION: "CONTINUE_SIGN_IN_WITH_MFA_SELECTION", // The user must select their mode of MFA verification before signing in. Complete the process with confirmSignIn. -- If this MFA method is required but not set up.
  RESET_PASSWORD: "RESET_PASSWORD", // The user must reset their password via resetPassword.
  CONFIRM_SIGN_UP: "CONFIRM_SIGN_UP", // The user hasn't completed the sign-up flow fully and must be confirmed via confirmSignUp.
  COMPLETE_AUTO_SIGN_IN: "COMPLETE_AUTO_SIGN_IN", // The sign up process needs to complete by invoking the autoSignIn API.
  DONE: "DONE" // The sign in process has been completed.
});
