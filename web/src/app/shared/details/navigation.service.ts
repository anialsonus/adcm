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
import { BaseEntity, IAction, Job, JobObject, LogFile, TypeName } from '@app/core/types';
import { AdcmTypedEntity } from '@app/models/entity';
import { IIssues } from '@app/models/issue';
import { IssueHelper } from '@app/helpers/issue-helper';
import { ICluster } from '@app/models/cluster';

export const ISSUE_MESSAGE = 'Something is wrong with your cluster configuration, please review it.';

export interface IDetails {
  parent?: ICluster;
  typeName: TypeName;
  id: number;
  name: string;
  upgradable: boolean;
  upgrade: string;
  status: string | number;
  /** link to actionss */
  action: string;
  actions: IAction[];
  issue: IIssues;
  log_files?: LogFile[];
  objects: JobObject[];
  prototype_name: string;
  prototype_display_name: string;
  prototype_version: string;
  provider_id: number;
  bundle_id: number;
  hostcomponent: string;
  state: string;
}

const IssueSet: { [key: string]: string[] } = {
  service: ['required_service'],
  import: ['required_import'],
};

// type IconMenu = 'issue' | 'status';

// interface Icon {
//   id: IconMenu;
//   isShow: boolean;
//   color: ThemePalette;
//   name: string;
// }

export interface INavItem {
  id?: number;
  title: string;
  url: string;
  issue?: string;
  status?: number;
  statusMessage?: string;
  action?: () => void;
}

export interface IStyledNavItem {
  class?: string;
  entity?: AdcmTypedEntity;
}

const all = [
  { id: 0, title: 'Main', url: 'main' },
  { id: 8, title: 'License', url: 'license' },
  { id: 4, title: 'Configuration', url: 'config' },
  { id: 5, title: 'Configuration groups', url: 'group_config' },
  { id: 6, title: 'Status', url: 'status' },
  { id: 7, title: 'Import', url: 'import' },
  { id: 1, title: 'Services', url: 'service' },
  { id: 2, title: 'Hosts', url: 'host' },
  { id: 3, title: 'Hosts - Components', url: 'host_component' },
];

const [main, license, config, group_config, m_status, m_import, services, hosts, host_components] = all;

const components = {
  id: 8,
  title: 'Components',
  url: 'component',
};

export const Config = {
  menu: {
    cluster: [main, config, group_config, m_status, m_import, services, hosts, host_components].sort((a, b) => a.id - b.id),
    service: [main, components, config, group_config, m_status, m_import],
    group_config: [hosts, config],
    host: [main, config, m_status],
    provider: [main, config, group_config],
    bundle: [main, license],
    servicecomponent: [main, config, group_config, m_status],
    component: [main, config, group_config, m_status],
  },
};

@Injectable()
export class NavigationService {
  findIssue = (url: string, issue: IIssues) => Object.keys(issue).some((p) => p === url || (IssueSet[url] && IssueSet[url].some((a) => a === p)));
  getIssueMessage = (flag: boolean) => (flag ? ISSUE_MESSAGE : '');

  getLeft(current: Partial<BaseEntity>): INavItem[] {
    const getMenu = (c: Partial<BaseEntity>) => {
      const forJob = (job: Job) => job.log_files.map((a) => ({
        title: `${a.name} [ ${a.type} ]`,
        url: `${a.id}`,
        action: () => (location.href = a.download_url)
      }));
      const def = (typeName: TypeName, issue: IIssues, status: number) =>
        Config.menu[typeName].map((i: INavItem) => ({
          ...i,
          issue: this.findIssue(i.url, issue),
          status,
        }));
      return c.typeName === 'job' ? forJob(c as Job) : def(c.typeName, c.issue || {}, +c.status);
    };
    return getMenu(current);
  }

  getTop(current: IDetails): INavItem[] {
    const issue = (i: IIssues) => (IssueHelper.isIssue(i) ? ISSUE_MESSAGE : '');
    const link = (p: { typeName: string; id?: number }) => (p ? `/${p.typeName}/${p.id}` : '');
    const typeObj = (type: string, prev: string) => ({ url: `${prev}/${type}`, title: `${type}s` });
    const fullLink = (c: { parent?: ICluster; typeName: TypeName; id?: number; name?: string; issue?: IIssues }): INavItem[] => [
      typeObj(c.typeName === 'job' ? 'task' : c.typeName, link(c.parent)),
      {
        id: c.id,
        url: `${link(c.parent)}${link(c)}`,
        title: c.name,
        issue: issue(c.issue),
      },
    ];
    return [current.parent, current].reduce((p, c) => [...p, ...(c ? fullLink(c) : [])], []);
  }
}
