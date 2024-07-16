import { readOnly } from '@ember/object/computed';
import { set } from '@ember/object';
import { inject as service } from '@ember/service';
import Base from 'ember-simple-auth/authenticators/base';

export default class CognitoAuthenticator extends Base {
    @service cognito;
    @readOnly('cognito.auth') auth;
    @readOnly('cognito.poolId') poolId;
    @readOnly('cognito.clientId') clientId;
    @readOnly('cognito.authenticationFlowType') authenticationFlowType;

    async restore() {
        return this.cognito.restoreSession();
    }

    async authenticate(params) {
        const { username, password, nextStep } = params;

        if (nextStep) {
            return this.cognito.handleNextStep(nextStep, params);
        }

        return this.cognito.signIn(username, password);
    }

    async invalidate(data) {
        await this.cognito.signOut();
        set(this, 'cognito.user', undefined);
        return data;
    }
}
