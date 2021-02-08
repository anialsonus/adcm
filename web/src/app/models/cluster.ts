import { IAction } from './action';
import { Entity } from '@adwp-ui/widgets';

export interface ICluster extends Entity {
  action: string;
  actions: IAction[];
  bind: string;
  bundle_id: number;
  config: string;
  description: string;
  edition: string;
  host: string;
  hostcomponent: string;
  imports: string;
  issue: any;
  license: string;
  name: string;
  prototype: string;
  prototype_display_name: string;
  prototype_id: number;
  prototype_name: string;
  prototype_version: string;
  service: string;
  serviceprototype: string;
  state: string;
  status: number;
  status_url: string;
  upgradable: boolean;
  upgrade: string;
  url: string;
}
