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
import { Component, Input, ViewChild } from '@angular/core';
import { FieldService } from '@app/shared/configuration/services/field.service';
import { ConfigFieldsComponent } from '@app/shared/configuration/fields/fields.component';
import { IUpgrade } from "@app/shared/components";

@Component({
  selector: 'app-upgrade-master-config',
  template: `
    <div class="config-tools">
      <mat-checkbox [(ngModel)]="advanced" *ngIf="fields.isAdvanced">Advanced</mat-checkbox>
    </div>
    <app-config-fields #fields [model]="upgrade?.config" [ngStyle]="{ display: 'inherit' }"></app-config-fields>
  `,
})
export class UpgradeMasterConfigComponent {
  @Input() upgrade: IUpgrade;

  @ViewChild('fields') fields: ConfigFieldsComponent = {} as ConfigFieldsComponent;

  set advanced(value: boolean) {
    this.config.filterApply(this.fields.dataOptions, { advanced: value, search: '' });
  }

  constructor(private config: FieldService) {}
}
