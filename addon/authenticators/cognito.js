import { readOnly } from '@ember/object/computed';
import { set } from '@ember/object';
import { inject as service } from '@ember/service';
import Base from 'ember-simple-auth/authenticators/base';

const currentUserEmailKey = "CognitoAuthenticator.currentUserEmail";

export default class CognitoAuthenticator extends Base {
    @service cognito;
    @readOnly('cognito.auth') auth;
    @readOnly('cognito.poolId') poolId;
    @readOnly('cognito.clientId') clientId;
    @readOnly('cognito.authenticationFlowType') authenticationFlowType;

    async restore({ poolId, clientId }) {
        // this.cognito.configure({
        //     userPoolId: poolId,
        //     userPoolWebClientId: clientId,
        // });
        const user = await this.auth.getCurrentUser();
        return this._resolveAuth(user);
    }

    _makeAuthData(session) {
        const sessionDetails = {
            poolId: this.poolId,
            clientId: this.clientId,
            access_token: session.tokens.idToken?.toString(),
        };

        const deviceKey = session.tokens.accessToken?.payload.device_key ?? "NOKEY";

        this._storeDeviceKey(deviceKey);
        localStorage.removeItem(currentUserEmailKey);

        return sessionDetails;
    }

    _storeDeviceKey(deviceKey) {
        const key = this._createDeviceStorageKey();
        localStorage.setItem(key, deviceKey);
    }

    _getDeviceKey() {
        const key = this._createDeviceStorageKey();
        return localStorage.getItem(key) ?? "NOKEY";
    }

    _createDeviceStorageKey() {
        const prefix = "CognitoIdentityServiceProvider";
        const clientId = this.cognito.amplify.getConfig().Auth.Cognito.userPoolClientId;;
        const userEmail = localStorage.getItem('currentUserEmail');
        return `${prefix}.${clientId}.${userEmail}.deviceKey`;
    }

    async _resolveAuth() {
        const { cognito } = this;

        const user = await this.auth.getCurrentUser();
        cognito._setUser(user);

        const session = await cognito.getCurrentSession();

        return this._makeAuthData(session);
    }

    _handleSignIn(user) {
        if (user.nextStep === CognitoNextStepsV6.DONE) {
            return this._resolveAuth();
        }

        return this._handleNextStep(user.nextStep, user)
    }

    async _handleNewPasswordRequired({ password, nextStep: { user } }) {
        const user2 = await this.auth.completeNewPassword({ user, password });
        return this._handleSignIn(user2);
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

    _handleNextStep(nextStep, params) {
        if (nextStep === 'refresh') {
            return this._handleRefresh();
        } else if (nextStep.signInStep === CognitoNextStepsV6.DONE) {
            return this._resolveAuth();
        } else if (nextStep === CognitoNextStepsV6.COMPLETE_AUTO_SIGN_IN) {
            return this.cognito.autoSignIn();
        } else if (nextStep.signInStep === CognitoNextStepsV6.CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED) {
            return this._handleNewPasswordRequired(params);
        } else if (nextStep.signInStep === CognitoNextStepsV6.CONFIRM_SIGN_IN_WITH_SMS_CODE 
                    || nextStep.signInStep === CognitoNextStepsV6.CONFIRM_SIGN_IN_WITH_TOTP_CODE
                    || nextStep.signInStep === CognitoNextStepsV6.CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE) {
            return this._handleChallengeMfa(nextStep, params);
        } else {
            throw new Error(`Unsupported nextStep ${nextStep?.signInStep}`);
        }
    }

    async _handleChallengeMfa(nextStep, params) {
        if (nextStep.additionalInfo.challengeName === "DEVICE_TRACKING_CHALLENGE") {
            const deviceKey = this._getDeviceKey();
            return this._submitChallengeResponse(deviceKey);
        } else if (params?.answer) {
            return this._submitChallengeResponse(params.answer);
        }
        
        throw { nextStep };
    }

    async _submitChallengeResponse(answer) {
        let authResult = await this.auth.confirmSignIn({ challengeResponse: answer });
        
        if (authResult.nextStep === CognitoNextStepsV6.DONE) {
            return this._resolveAuth();
        }

        return this._handleNextStep(authResult.nextStep)
    }

    async authenticate(params) {
        // this.cognito.configure();

        const { username, password, nextStep } = params;

        localStorage.setItem("currentUserEmail", username);

        if (nextStep) {
            return this._handleNextStep(nextStep, params);
        }

        await this.auth.signOut();

        localStorage.setItem(currentUserEmailKey, username);
        const authResult = await this.auth.signIn({
            username,
            password,
            options: {
                authFlowType: 'CUSTOM_WITH_SRP'
            }
        });

        return this._handleSignIn(authResult);
    }

    async invalidate(data) {
        await this.cognito.user.signOut();
        set(this, 'cognito.user', undefined);
        return data;
    }
}
