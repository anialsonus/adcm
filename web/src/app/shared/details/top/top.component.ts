// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
import { Component, Input } from '@angular/core';
import { Cluster, IAction, isIssue, Issue } from '@app/core/types';
import { UpgradeItem } from '@app/shared/components';

import { IDetails, INavItem, NavigationService } from '../navigation.service';

@Component({
  selector: 'app-details-top',
  template: `
    <app-crumbs [navigation]="items"></app-crumbs>
    <div class="example-spacer"></div>
    <app-upgrade *ngIf="upgradable" [dataRow]="upgrade" xPosition="after"></app-upgrade>
    <!-- <app-actions [source]="actions || []" [isIssue]="eIssue" [cluster]="cluster"></app-actions> -->
  `,
  styles: [':host {display: flex;width: 100%;}'],
})
export class TopComponent {
  items: INavItem[];
  cluster: { id: number; hostcomponent: string };
  eIssue: boolean;
  upgrade: UpgradeItem;
  @Input() upgradable: boolean;
  @Input() actions: IAction[] = [];

  @Input() set isIssue(v: boolean) {
    this.eIssue = v;
    if (this.upgrade) this.upgrade.issue = (v ? { issue: '' } : {}) as Issue;
    if (this.items) {
      const a = this.items.find((b) => b.id);
      if (a) a.issue = this.navigation.getIssueMessage(v);
    }
  }

  @Input() set current(c: IDetails) {
    if (c) {
      this.items = this.navigation.getTop(c);
      const { id, hostcomponent, issue, upgradable, upgrade } = c.parent || (c as Partial<Cluster>);
      this.cluster = { id, hostcomponent };
      this.upgradable = upgradable;
      this.eIssue = isIssue(issue);
      this.upgrade = { issue, upgradable, upgrade };
    }
  }
  constructor(private navigation: NavigationService) {}
}
