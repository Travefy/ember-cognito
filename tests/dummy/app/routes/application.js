import Route from '@ember/routing/route';
import { inject as service } from '@ember/service';
import { StageConfig } from '../objects/dummy-cognito-config';

export default class Application extends Route {
  @service currentUser;
  @service session;
  @service cognito;

  async beforeModel() {
    this.cognito.configure(StageConfig);
    await this.session.setup();
    try {
      await this.currentUser.load();
    } catch (err) {
      await this.invalidate();
    }
  }
}
