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
import { IYspec } from './yspec/yspec.service';

export type stateType = 'created' | 'locked';

export type ConfigValueTypes =
  | 'structure'
  | 'group'
  | 'dict'
  | 'string'
  | 'integer'
  | 'int'
  | 'float'
  | 'boolean'
  | 'option'
  | 'json'
  | 'map'
  | 'list'
  | 'file'
  | 'text'
  | 'password';
export type simpleTypes = string | number | boolean;
export type resultTypes = simpleTypes | simpleTypes[] | object;
export type controlType = 'boolean' | 'textbox' | 'textarea' | 'json' | 'password' | 'list' | 'map' | 'dropdown' | 'file' | 'text' | 'structure';

export type TValue = string | number | boolean | object | any[];

/**
 *```
 {
    invisible?: boolean;
    no_confirm?: boolean;
    advanced?: boolean;
 }
 ```
 *
 */
export interface IUIoptions {
  invisible?: boolean;
  no_confirm?: boolean;
  advanced?: boolean;
}

/**
 * ```
 {
    min?: number;
    max?: number;
    option?: any;
    read_only?: stateType[];   // created | locked
    yspec?: IYspec;
    rules?: any;
    active?: boolean;
}
 * ```
 */
export interface ILimits {
  min?: number;
  max?: number;
  option?: any;
  read_only?: stateType[];
  yspec?: IYspec;
  rules?: any;
  active?: boolean;
}

export interface ValidatorInfo {
  pattern?: string | RegExp;
  required?: boolean;
  max?: number;
  min?: number;
}

/**
 * Property config object from backend
 */
export interface IFieldStack {
  type: ConfigValueTypes;
  name: string;
  subname: string;
  display_name: string;
  default: TValue;
  value: TValue;
  required: boolean;
  description?: string;
  limits?: ILimits;
  read_only: boolean;
  ui_options?: IUIoptions;
  activatable: boolean;
}

/**
 * The object for config for backend
 */
export interface IConfig {
  id?: number;
  date?: string;
  description?: string;
  config: IFieldStack[];
  attr?: IConfigAttr;
}

/**
 *```
{
    [group: string]: { active: boolean };
}
```
 */
export interface IConfigAttr {
  [group: string]: { active: boolean };
}

export interface ConfigOptions {
  key?: string;
  type: ConfigValueTypes;
  display_name: string;
  name: string;
  subname: string;
  hidden: boolean;
  read_only: boolean;
  ui_options?: IUIoptions;
  description?: string;
  activatable?: boolean;
  required: boolean;
}

export interface PanelOptions extends ConfigOptions {
  options: (FieldOptions | PanelOptions)[];
  active: boolean;
}

/**
 * For Material form controls
 */
export interface FieldOptions extends ConfigOptions {
  default: TValue;
  value: TValue;
  controlType: controlType;
  validator: ValidatorInfo;
  limits?: ILimits;
  compare: Compare[];
}

export interface CompareConfig extends IConfig {
  color: string;
}

interface Compare {
  id: number;
  date: string;
  value: string;
  color: string;
}
