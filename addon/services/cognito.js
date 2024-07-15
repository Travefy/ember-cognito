import Service, { inject as service } from '@ember/service';
import CognitoUser from '../utils/cognito-user';
import { normalizeAttributes } from '../utils/utils';
import { Amplify } from 'aws-amplify';
import Auth from 'aws-amplify/auth';
import { set } from '@ember/object';
import { reject } from 'rsvp';


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

const isTesting = false; 

/**
 * @public
 * This is a container for easily accessing the logged-in CognitoUser object,
 * as well as creating others using signUp().
 */

export default class CognitoService extends Service {
  @service session;
  amplify = Amplify;
  auth = Auth;
  nextStepOptions = CognitoNextSteps;

  willDestroy() {
    super.willDestroy(...arguments);
    this.stopRefreshTask();
  }

  /**
   * Configures the Amplify library with the pool & client IDs, and any additional
   * configuration.
   * @param awsconfig Extra AWS configuration.
   */
  configure(awsconfig) {
    const { poolId, clientId } = this;
    const params = Object.assign(
      {
        userPoolId: poolId,
        userPoolClientId: clientId,
      },
      awsconfig
    );
    this.amplify.configure({
      Auth: {
        Cognito: {
          ...params,
        },
      },
    });
  }

  /**
   * Method for signing up a user.
   *
   * @param username User's username
   * @param password Plain-text initial password entered by user.
   * @param attributes New user attributes.
   * @param validationData Application metadata.
   * @param autoSignIn Set to true if you plan to call the autoSignIn event after signUp / confirmSignUp.
   */
  async signUp(
    username,
    password,
    attributes,
    validationData,
    autoSignIn = true
  ) {
    // this.configure();
    const userAttributes = normalizeAttributes(attributes);
    const result = await this.auth.signUp({
      username,
      password,
      options: {
        userAttributes: {
          email: userAttributes.email,
        },
        validationData,
        autoSignIn,
      },
    });

    if (result.nextStep === 'DONE') {
      const user = await this.auth.getCurrentUser();
      result.user = this._setUser(user);
    }

    return result;
  }

  /**
   * Confirm signup for user.
   * @param username User's username.
   * @param code The confirmation code.
   * @returns {Promise<any>}
   */
  async confirmSignUp(username, code, options) {
    // this.configure();
    return this.auth.confirmSignUp({ username, code, options });
  }

  /**
   * Auto sign in after sign up completion, using the signUp result.
   * @returns {Promise<any>}
   */
  async autoSignIn() {
    const result = await this.auth.autoSignIn();
    const user = await this.auth.getCurrentUser();
    result.user = this._setUser(user);
    return result;
  }

  /**
   * Resends the sign up code.
   * @param username User's username.
   * @returns {*|Promise<string>}
   */
  resendSignUp(username) {
    // this.configure();
    return this.auth.resendSignUpCode({ username });
  }

  /**
   * Sends a user a code to reset their password.
   * @param username
   * @returns {*|Promise<any>|RSVP.Promise|void}
   */
  forgotPassword(username) {
    // this.configure();
    return this.auth.resetPassword({ username });
  }

  /**
   * Submits a new password.
   * @param username User's username.
   * @param confirmationCode The verification code sent by forgotPassword.
   * @param newPassword The user's new password.
   * @returns {*|Promise<void>|void}
   */
  forgotPasswordSubmit(username, confirmationCode, newPassword) {
    // this.configure();
    return this.auth.confirmResetPassword({
      username,
      confirmationCode,
      newPassword,
    });
  }

  /*
    Get / Refresh the current session
  */
  async getCurrentSession() {
    return await this.auth.fetchAuthSession();
  }

  /**
   * A helper that resolves to the logged in user's id token.
   */
  async getJwtToken() {
    const user = this.user;
    if (user) {
      const session = await this.getCurrentSession();
      return session.tokens.idToken?.toString();
    } else {
      return reject('user not authenticated');
    }
  }

  _setUser(awsUser) {
    // Creates and sets the Cognito user.
    const user = CognitoUser.create({ auth: this.auth, user: awsUser });
    set(this, 'user', user);
    return user;
  }
}
