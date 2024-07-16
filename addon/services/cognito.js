import Service, { inject as service } from '@ember/service';
import CognitoUser from '../utils/cognito-user';
import { normalizeAttributes } from '../utils/utils';
import { Amplify } from 'aws-amplify';
import Auth from 'aws-amplify/auth';
import { set } from '@ember/object';
import { reject } from 'rsvp';
import { isPresent, isNone } from '@ember/utils';

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

export default class CognitoService extends Service {
    @service session;

    amplify = Amplify;
    auth = Auth;
    nextStepOptions = CognitoNextSteps;
    currentUserEmail = null;

    willDestroy() {
        super.willDestroy(...arguments);
        this.stopRefreshTask();
    }

    /**
     * Configures the Amplify library with the pool & client IDs, and any additional
     * configuration.
     * @param configOverride Extra AWS configuration.
     */

    configure(configOverride) {
        if (this._isConfigured() && isNone(configOverride)) {
            return;
        }

        const defaultConfig = {
            userPoolId: this.poolId,
            userPoolClientId: this.clientId,
        };

        const params = Object.assign(
            defaultConfig,
            configOverride
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
     * Method for signing in a user.
     *
     * @param username User's username
     * @param password Plain-text initial password entered by user.
     */
    async signIn(username, password) {
        this.currentUserEmail = username;
        
        const authResult = await this.auth.signIn({
            username,
            password,
            options: {
                authFlowType: 'CUSTOM_WITH_SRP'
            }
        });

        return this._handleSignIn(authResult);
    }

    /**
     * Method for signing out a user.
     */

    async signOut() {
        return this.auth.signOut();
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

        return this.handleNextStep(result.nextStep);
    }

    /**
     * Confirm signup for user.
     * @param username User's username.
     * @param confirmationCode The confirmation code.
     * @returns {Promise<any>}
     */
    async confirmSignUp(username, confirmationCode, options) {
        return this.auth.confirmSignUp({ username, confirmationCode, options });
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
        return this.auth.confirmResetPassword({
            username,
            confirmationCode,
            newPassword,
        });
    }

    async handleNextStep(nextStep, params) {
        if (nextStep === 'refresh') {
            return this._handleRefresh();
        } else if (nextStep.signInStep === this.nextStepOptions.DONE) {
            return this._resolveAuth();
        } else if (nextStep.signUpStep === this.nextStepOptions.COMPLETE_AUTO_SIGN_IN) {
            return this.autoSignIn();
        } else if (nextStep.signInStep === this.nextStepOptions.CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED) {
            return this._handleNewPasswordRequired(params);
        } else if (nextStep.signInStep === this.nextStepOptions.CONFIRM_SIGN_IN_WITH_SMS_CODE 
                    || nextStep.signInStep === this.nextStepOptions.CONFIRM_SIGN_IN_WITH_TOTP_CODE
                    || nextStep.signInStep === this.nextStepOptions.CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE) {
            return this._handleChallengeMfa(nextStep, params);
        } else {
            throw new Error(`Unsupported nextStep ${nextStep?.signInStep}`);
        }
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

    async restoreSession() {
        const user = await this.auth.getCurrentUser();
        return this._resolveAuth(user);    
    }

    async _handleRefresh() {
        const { cognito } = this;
        const { user } = cognito;

        const session = await user.getSession(); // Get the session, which will refresh it if necessary

        if (session.isValid()) {
            return this._makeAuthData(session);
        } else {
            throw new Error('session is invalid');
        }
    }

    async _handleSignIn(user) {
        if (user.nextStep === this.nextStepOptions.DONE) {
            return this._resolveAuth();
        }

        return this.handleNextStep(user.nextStep, user)
    }

    async _handleNewPasswordRequired({ password, nextStep: { user } }) {
        const user2 = await this.auth.completeNewPassword({ user, password });
        return this._handleSignIn(user2);
    }

    async _handleChallengeMfa(nextStep, params) {
        if (nextStep.signInStep === this.nextStepOptions.CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE && nextStep.additionalInfo.challengeName === "DEVICE_TRACKING_CHALLENGE") {
            const deviceKey = this._getDeviceKey();
            return this._submitChallengeResponse(deviceKey);
        } else if (params?.answer) {
            return this._submitChallengeResponse(params.answer);
        }
        
        throw { nextStep };
    }

    async _submitChallengeResponse(answer) {
        let authResult = await this.auth.confirmSignIn({ challengeResponse: answer });
        
        if (authResult.nextStep === this.nextStepOptions.DONE) {
            return this._resolveAuth();
        }

        return this.handleNextStep(authResult.nextStep)
    }
    
    async _resolveAuth() {
        const user = await this.auth.getCurrentUser();
        this._setUser(user);

        const session = await this.getCurrentSession();

        return this._makeAuthData(session);
    }

    _makeAuthData(session) {
        const sessionDetails = {
            poolId: this.poolId,
            clientId: this.clientId,
            access_token: session.tokens.idToken?.toString(),
        };

        const deviceKey = session.tokens.accessToken?.payload.device_key ?? "NOKEY";

        this._storeDeviceKey(deviceKey);

        return sessionDetails;
    }

    _createDeviceStorageKey() {
        const prefix = "CognitoIdentityServiceProvider";
        const clientId = this.amplify.getConfig().Auth.Cognito.userPoolClientId;;
        const userEmail = this.currentUserEmail;
        return `${prefix}.${clientId}.${userEmail}.deviceKey`;
    }
    
    _storeDeviceKey(deviceKey) {
        const key = this._createDeviceStorageKey();
        localStorage.setItem(key, deviceKey);
    }

    _getDeviceKey() {
        const key = this._createDeviceStorageKey();
        return localStorage.getItem(key) ?? "NOKEY";
    }

    _isConfigured() {
        return isPresent(this.amplify.getConfig().Auth);
    }
}
