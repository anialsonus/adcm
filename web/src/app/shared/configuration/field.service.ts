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
import { AbstractControl, FormBuilder, FormGroup, ValidatorFn, Validators } from '@angular/forms';
import { getControlType, getPattern, isEmptyObject } from '@app/core/types';

import { ConfigOptions, resultTypes, ConfigValueTypes, controlType, FieldOptions, FieldStack, IConfig, IConfigAttr, PanelOptions, ValidatorInfo, ILimits } from './types';
import { matchType, simpleType } from './yspec/yspec.service';

export type itemOptions = FieldOptions | PanelOptions;

export interface IOutput {
  [key: string]: resultTypes;
}

export interface IToolsEvent {
  name: string;
  conditions?: { advanced: boolean; search: string } | boolean;
}

@Injectable()
export class FieldService {
  constructor(private fb: FormBuilder) {}

  isVisibleField = (a: ConfigOptions) => !a.ui_options || !a.ui_options.invisible;
  isInvisibleField = (a: ConfigOptions) => a.ui_options && a.ui_options.invisible;
  isAdvancedField = (a: ConfigOptions) => a.ui_options && a.ui_options.advanced && !a.ui_options.invisible;
  isHidden = (a: FieldStack) => a.ui_options && (a.ui_options.invisible || a.ui_options.advanced);

  getPanels(data: IConfig): itemOptions[] {
    if (data && data.config) {
      const fo = data.config.filter((a) => a.type !== 'group' && a.subname);
      return data.config
        .filter((a) => a.name !== '__main_info')
        .reduce((p, c) => {
          if (c.subname) return p;
          if (c.type !== 'group') return [...p, this.getFieldBy(c)];
          else return [...p, this.fillDataOptions(c, fo, data.attr)];
        }, []);
    }
    return [];
  }

  fillDataOptions(a: FieldStack, fo: FieldStack[], attr: IConfigAttr) {
    return {
      ...a,
      hidden: this.isHidden(a),
      active: a.activatable ? attr[a.name]?.active : true,
      options: fo
        .filter((b) => b.name === a.name)
        .map((b) => this.getFieldBy(b))
        .map((c) => ({ ...c, name: c.subname })),
    };
  }

  getFieldBy(item: FieldStack): FieldOptions {
    const params: FieldOptions = {
      ...item,
      key: `${item.subname ? item.subname + '/' : ''}${item.name}`,
      value: this.getValue(item.type)(item.value, item.default, item.required),
      validator: {
        required: item.required,
        min: item.limits ? item.limits.min : null,
        max: item.limits ? item.limits.max : null,
        pattern: getPattern(item.type),
      },
      controlType: getControlType(item.type as matchType),
      hidden: item.name === '__main_info' || this.isHidden(item),
      compare: [],
    };
    return params;
  }

  setValidator(field: { validator: ValidatorInfo; controlType: controlType }) {
    const v: ValidatorFn[] = [];

    if (field.validator.required) v.push(Validators.required);
    if (field.validator.pattern) v.push(Validators.pattern(field.validator.pattern));
    if (field.validator.max !== undefined) v.push(Validators.max(field.validator.max));
    if (field.validator.min !== undefined) v.push(Validators.min(field.validator.min));

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
          if (control.value && Object.keys(control.value).length && Object.keys(control.value).some((a) => !a)) {
            return { parseKey: true };
          } else return null;
        };
      };
      v.push(parseKey());
    }

    return v;
  }

  toFormGroup(options: itemOptions[] = []): FormGroup {
    const isVisible = (a: itemOptions) => !a.read_only && !(a.ui_options && a.ui_options.invisible);
    const check = (a: itemOptions) => ('options' in a ? (a.activatable ? true : isVisible(a) ? a.options.some((b) => check(b)) : false) : isVisible(a));
    return this.fb.group(
      options.reduce((p, c) => this.runByTree(c, p), {}),
      {
        validator: () => (options.filter(check).length === 0 ? { error: 'Form is empty' } : null),
      }
    );
  }

  // TODO: impure
  runByTree(field: itemOptions, controls: { [key: string]: {} }): { [key: string]: {} } {
    if ('options' in field) {
      controls[field.name] = this.fb.group(
        field.options.reduce((p, a) => {
          if ('options' in a) this.fb.group(this.runByTree(a, p));
          else this.fillForm(a, p);
          return p;
        }, {})
      );
      return controls;
    } else {
      return this.fillForm(field, controls);
    }
  }

  fillForm(field: FieldOptions, controls: {}) {
    const name = field.subname || field.name;
    controls[name] = this.fb.control(field.value, this.setValidator(field));
    if (field.controlType === 'password') {
      if (!field.ui_options || (field.ui_options && !field.ui_options.no_confirm)) {
        controls[`confirm_${name}`] = this.fb.control(field.value, this.setValidator(field));
      }
    }
    return controls;
  }

  filterApply(dataOptions: itemOptions[], c: { advanced: boolean; search: string }): itemOptions[] {
    return dataOptions.filter((a) => this.isVisibleField(a)).map((a) => this.handleTree(a, c));
  }

  handleTree(a: itemOptions, c: { advanced: boolean; search: string }) {
    if ('options' in a) {
      const result = a.options.map((b) => this.handleTree(b, c));
      if (c.search) a.hidden = a.options.filter((b) => !b.hidden).length === 0;
      else a.hidden = this.isAdvancedField(a) ? !c.advanced : false;
      return result;
    } else if (this.isVisibleField(a)) {
      a.hidden = !(a.display_name.toLowerCase().includes(c.search.toLowerCase()) || JSON.stringify(a.value).includes(c.search));
      if (!a.hidden && this.isAdvancedField(a)) a.hidden = !c.advanced;
      return a;
    }
  }

  getValue(name: string) {
    const def = (value: number | string) => (value === null || value === undefined ? '' : String(value));

    const data = {
      boolean: (value: boolean | null, d: boolean | null, required: boolean) => {
        const allow = String(value) === 'true' || String(value) === 'false' || String(value) === 'null';
        return allow ? value : required ? d : null;
      },
      json: (value: string) => (value === null ? '' : JSON.stringify(value, undefined, 4)),
      map: (value: object, de: object) => (!value ? de : value),
      list: (value: string[], de: string[]) => (!value ? de : value),
      structure: (value: any) => value,
    };

    return data[name] ? data[name] : def;
  }

  getFieldsBy(items: Array<FieldStack>): FieldOptions[] {
    return items.map((o) => this.getFieldBy(o));
  }

  /**
   * Cast to source type
   */
  parseValue(output: IOutput, source: { name: string; subname: string; type: ConfigValueTypes; read_only: boolean; limits?: ILimits; value: any }[]): IOutput {
    const findField = (name: string, p?: string): Partial<FieldStack> => source.find((a) => (p ? a.name === p && a.subname === name : a.name === name) && !a.read_only);

    const runYspecParse = (v: any, rules: any) => this.runYspec(v, rules);

    const runParse = (v: IOutput, parentName?: string): IOutput => {
      const checkType = (data: resultTypes | IOutput, field: Partial<FieldStack>): resultTypes => {
        const { type } = field;
        if (type === 'structure') return runYspecParse(data, field.limits.rules);
        else if (type === 'group') return this.checkValue(runParse(data as IOutput, field.name), type);
        else return this.checkValue(data, type);
      };

      const runByValue = (p: IOutput, c: string) => {
        const f = findField(c, parentName);
        const r = f ? checkType(v[c], f) : null;
        return r !== null ? { ...p, [c]: r } : p;
      };

      return Object.keys(v).reduce(runByValue, {});
    };

    const __main_info = findField('__main_info');
    return runParse(__main_info?.required ? { ...output, __main_info: __main_info.value } : { ...output });
  }

  runYspec(value: resultTypes, rules: any) {
    switch (rules.type) {
      case 'list': {
        return (value as Array<simpleType>).filter((a) => !!a).map((a) => this.runYspec(a, rules.options));
      }
      case 'dict': {
        return Object.keys(value).reduce((p, c) => {
          const v = this.runYspec(
            value[c],
            rules.options.find((b: any) => b.name === c)
          );
          return v !== null ? { ...p, [c]: v } : { ...p };
        }, {});
      }
      default: {
        return this.checkValue(value, rules.type);
      }
    }
  }

  checkValue(value: resultTypes, type: ConfigValueTypes): resultTypes {
    if (value === '' || value === null || isEmptyObject(value)) return null;
    if (typeof value === 'boolean') return value;
    else if (typeof value === 'string')
      switch (type) {
        case 'option':
          return !isNaN(+value) ? parseInt(value, 10) : value;
        case 'integer':
        case 'int':
          return parseInt(value, 10);
        case 'float':
          return parseFloat(value);
        case 'json':
          return JSON.parse(value);
      }
    else
      switch (type) {
        case 'map':
          return Object.keys(value)
            .filter((a) => !!a)
            .reduce((p, c) => ({ ...p, [c]: value[c] }), {});

        case 'list':
          return Array.isArray(value) ? (value as Array<string>).filter((a) => !!a) : null;
      }

    return value;
  }
}
