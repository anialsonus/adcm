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
import { Directive, Input, OnInit } from '@angular/core';
import { clearEmptyField } from '@app/core/types';
import { BaseFormDirective } from '@app/shared/add-component/base-form.directive';
import { take } from 'rxjs/operators';
import { Params } from '@angular/router';

@Directive({
  selector: '[appRbacForm]',
})
export class RbacFormDirective<T extends { url: string } = { url: string }> extends BaseFormDirective implements OnInit {
  @Input()
  value: T;

  filter: Params = {};

  get title(): string {
    return this.value ? 'Update' : 'Add';
  }

  ngOnInit(): void {
    if (this.value) {
      // ToDo(lihih) the "adwp-list" should not change the composition of the original model.
      //  Now he adds the "checked" key to the model
      const formValue = { ...this.value };
      Object.keys(formValue).forEach((prop) => {
        if (!this.form.controls.hasOwnProperty(prop)) delete formValue[prop];
      })
      this.form.setValue(formValue);
    }
  }

  rbacBeforeSave(value: T): Partial<T> {
    return value;
  }

  save(): void {
    const data = clearEmptyField(this.rbacBeforeSave(this.form.value));

    if (this.value) {
      this.service
        .update(this.value.url, data)
        .pipe(take(1))
        .subscribe((_) => this.onCancel());
    } else {
      this.service
        .add(data)
        .pipe(take(1))
        .subscribe((_) => this.onCancel());
    }
  }

  updateFilter(key: string, value: string): void {
    this.filter = { ...this.filter, [key]: value?.trim() };
  }
}
