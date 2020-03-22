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
import { Component, EventEmitter, Input, OnInit, Output } from '@angular/core';

import { IControl } from './root.component';
import { controlType, ValidatorInfo } from '../types';
import { IYField } from '../yspec/yspec.service';

@Component({
  selector: 'app-item-scheme',
  template: `
    <ng-container [formGroup]="item.form">
      <ng-container *ngIf="item.parent === 'list'; else other">
        <mat-form-field *ngIf="controlType === 'textbox'">
          <input matInput [formControlName]="index" [value]="item.value" />
          <button *ngIf="item.parent === 'list'" mat-icon-button matSuffix color="primary" (click)="emmit()">
            <mat-icon>highlight_off</mat-icon>
          </button>
        </mat-form-field>
      </ng-container>

      <ng-template #other>
        <div class="chbox-field" *ngIf="controlType === 'boolean'">
          <mat-checkbox [formControlName]="item.name" [checked]="item.value">{{ item.name }}</mat-checkbox>
        </div>
        <mat-form-field *ngIf="controlType === 'textbox'">
          <mat-label>{{ item.name }}</mat-label>
          <input matInput [formControlName]="item.name" />
          <mat-error *ngIf="!isValid">
            <mat-error *ngIf="hasError('required')">Field [{{ item.name }}] is required!</mat-error>
            <mat-error *ngIf="hasError('pattern')">Field [{{ item.name }}] is invalid!</mat-error>
            <mat-error *ngIf="hasError('min')">Field [{{ item.name }}] value cannot be less than {{ validator.min }}!</mat-error>
            <mat-error *ngIf="hasError('max')">Field [{{ item.name }}] value cannot be greater than {{ validator.max }}!</mat-error>
          </mat-error>
        </mat-form-field>
      </ng-template>
    </ng-container>
  `,
  styles: ['mat-form-field {margin: 6px 0 0; width: 100%}', '.chbox-field {margin:6px 0;}']
})
export class ItemComponent implements OnInit {
  @Input() item: IControl;
  @Input() index: number;
  @Output() remove = new EventEmitter<number>();

  controlType: controlType;
  validator: ValidatorInfo;

  ngOnInit() {
    const rules = this.item.rules as IYField;
    this.controlType = rules.controlType;
    this.validator = rules.validator;
    this.item.form.markAllAsTouched();
  }
  emmit() {
    this.remove.emit(this.index);
  }
  get isValid() {
    const field = this.item.form.controls[this.item.name];
    return field.valid && (field.dirty || field.touched);
  }

  hasError(title: string) {
    return this.item.form.controls[this.item.name].hasError(title);
  }
}
