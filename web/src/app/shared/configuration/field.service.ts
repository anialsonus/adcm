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
import { Injectable } from '@angular/core';
import { AbstractControl, FormControl, FormGroup, ValidatorFn, Validators } from '@angular/forms';
import { ConfigOptions, FieldOptions, FieldStack, IConfig, PanelOptions } from '@app/core/types';

export interface CompareConfig extends IConfig {
  color: string;
}

export interface IToolsEvent {
  name: string;
  conditions?: { advanced: boolean; search: string } | boolean;
}

@Injectable({ providedIn: 'root' })
export class FieldService {
  globalConfig: IConfig;
  panelOptions: PanelOptions[];
  formOptions: FieldOptions[];
  form = new FormGroup({});

  isVisibleField = (a: ConfigOptions) => !a.ui_options || !a.ui_options.invisible;
  isInvisibleField = (a: ConfigOptions) => a.ui_options && a.ui_options.invisible;
  isAdvancedField = (a: ConfigOptions) => a.ui_options && a.ui_options.advanced && !a.ui_options.invisible;
  isHidden = (a: FieldStack) => a.ui_options && (a.ui_options.invisible || a.ui_options.advanced);

  getPanels(data: IConfig) {
    this.globalConfig = data;
    this.panelOptions = [];

    if (data && data.config.length) {
      this.formOptions = data.config.filter(a => a.type !== 'group').map((a: FieldStack) => this.getFieldBy(a));

      this.panelOptions = data.config
        .filter(a => a.name !== '__main_info')
        .filter(a => a.type === 'group' || !a.subname)
        .map(a => ({
          name: a.name,
          label: a.display_name,
          read_only: a.read_only,
          hidden: this.isHidden(a),
          ui_options: a.ui_options,
          options: this.formOptions.filter(b => b.name === a.name),
          activatable: a.activatable,
          description: a.description
        }));
    }

    return this.panelOptions;
  }

  getFieldBy(item: FieldStack): FieldOptions {
    const params: FieldOptions = {
      ...item,
      key: `${item.subname ? item.subname + '/' : ''}${item.name}`,
      label: item.display_name,
      disabled: item.read_only,
      value: this.getValue(item.type)(item.value, item.default, item.required),
      validator: {
        required: item.required,
        min: item.limits ? item.limits.min : null,
        max: item.limits ? item.limits.max : null,
        pattern: this.getPattern(item.type)
      },
      controlType: this.controlType(item.type),
      hidden: item.name === '__main_info' || this.isHidden(item)
    };
    return params;
  }

  setValidator(field: FieldOptions) {
    const v: ValidatorFn[] = [];

    if (field.validator.required) v.push(Validators.required);
    if (field.validator.pattern) v.push(Validators.pattern(field.validator.pattern));
    if (field.validator.max) v.push(Validators.max(field.validator.max));
    if (field.validator.min) v.push(Validators.min(field.validator.min));

    if (field.controlType === 'json') {
      const jsonParse = (): ValidatorFn => {
        return (control: AbstractControl): { [key: string]: any } | null => {
          if (control.value) {
            try {
              JSON.parse(control.value);
              return null;
            } catch (e) {
              return { jsonParseError: { value: control.value } };
            }
          } else return null;
        };
      };
      v.push(jsonParse());
    }

    if (field.controlType === 'map') {
      const parseKey = (): ValidatorFn => {
        return (control: AbstractControl): { [key: string]: any } | null => {
          if (control.value && Object.keys(control.value).length && Object.keys(control.value).some(a => !a)) {
            return { parseKey: true };
          } else return null;
        };
      };
      v.push(parseKey());
    }

    return v;
  }

  toFormGroup(): FormGroup {
    this.form = new FormGroup({});
    this.formOptions.forEach(field => {
      this.form.setControl(field.key, new FormControl({ value: field.value, disabled: field.disabled }, this.setValidator(field)));
      if (field.controlType === 'password') {
        if (!field.ui_options || (field.ui_options && !field.ui_options.no_confirm)) {
          this.form.setControl(`confirm_${field.key}`, new FormControl(field.value || '', field.validator.required ? [Validators.required] : null));
        }
      }
    });
    return this.form;
  }

  filterApply(c: { advanced: boolean; search: string }): PanelOptions[] {
    this.panelOptions
      .filter(a => this.isVisibleField(a))
      .map(a => {
        // fields
        a.options
          .filter(b => this.isVisibleField(b))
          .map(b => {
            b.hidden = !(b.label.toLowerCase().includes(c.search.toLowerCase()) || JSON.stringify(b.value).includes(c.search));
            return b;
          })
          .filter(b => !b.hidden && this.isAdvancedField(b))
          .map(b => {
            b.hidden = !c.advanced;
          });

        //group
        if (c.search) {
          a.hidden = a.options.filter(b => !b.hidden).length === 0;
        } else {
          a.hidden = this.isAdvancedField(a) ? !c.advanced : false; // && a.options.filter(b => !b.hidden).length > 0);
        }
      });

    return [...this.panelOptions];

    // const fields = this.fields.fields.filter(a => a.options.name !== '__main_info').filter(a => a.options.type !== 'group');

    // this.applyFields(fields, c);

    // // advanced fields only
    // this.fields.panels
    //   .filter(p => p.ui_options && p.ui_options.advanced && !p.ui_options.invisible)
    //   .map(p => {
    //     p.hidden = !c.advanced;

    //     if (p.options.length === 1 && p.options[0].ui_options && !p.options[0].ui_options.invisible) {
    //       p.options[0].hidden = !c.advanced;
    //     }
    //     return p;
    //   });

    // // all fields without advanced and invisible
    // this.fields.groups.forEach(g => {
    //   this.applyFields(g.fields.toArray(), c);
    //   if (!g.panel.ui_options) g.panel.hidden = g.panel.options.filter(a => !a.hidden).length < 1;
    // });
  }

  // applyFields(fields: FieldComponent[], co: { advanced: boolean; search: string }) {
  //   fields
  //     .filter(a => !a.options.ui_options || !a.options.ui_options.invisible)
  //     .map(c => {
  //       c.options.hidden = !(c.options.label.includes(co.search) || JSON.stringify(c.options.value).includes(co.search));
  //       c.cdetector.markForCheck();
  //       return c;
  //     })
  //     .filter(a => !a.options.hidden && a.options.ui_options && a.options.ui_options.advanced)
  //     .map(a => {
  //       a.options.hidden = !co.advanced;
  //       a.cdetector.markForCheck();
  //       return a;
  //     });
  // }

  controlType(name: string): string {
    const ControlsTypes = {
      file: 'textarea',
      text: 'textarea',
      integer: 'textbox',
      float: 'textbox',
      string: 'textbox'
    };
    return ControlsTypes[name] || name;
  }

  getPattern(name: string): RegExp {
    const fn = {
      integer: () => new RegExp(/^\d+$/),
      float: () => new RegExp(/^[0-9]+(\.[0-9]+)?$/)
    };
    return fn[name] ? fn[name]() : null;
  }

  getValue(name: string) {
    const def = (value: number | string) => (value === null || value === undefined ? '' : String(value));

    const data = {
      boolean: (value: boolean | null, d: boolean | null, required: boolean) => {
        const allow = String(value) === 'true' || String(value) === 'false' || String(value) === 'null';
        return allow ? value : required ? d : null;
      },
      json: (value: string) => (value === null ? '' : JSON.stringify(value, undefined, 4)),
      map: (value: object, de: object) => (!value ? (!de ? {} : de) : value),
      list: (value: string[], de: string[]) => (!value ? (!de ? [] : de) : value)
    };

    return data[name] ? data[name] : def;
  }

  getFieldsBy(items: Array<FieldStack>): FieldOptions[] {
    return items.map(o => this.getFieldBy(o));
  }
}
