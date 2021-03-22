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
import { MatDialog } from '@angular/material/dialog';
import { ParamMap } from '@angular/router';
import { clearMessages, EventMessage, getMessage, SocketState } from '@app/core/store';
import { Bundle, Cluster, EmmitRow, Entities, Host as AdcmHost, TypeName } from '@app/core/types';
import { select, Store } from '@ngrx/store';
import { filter, mergeMap, switchMap, tap } from 'rxjs/operators';
import { IListResult } from '@adwp-ui/widgets';
import { takeUntil } from 'rxjs/operators';
import { Sort } from '@angular/material/sort';
import { Observable, Subject } from 'rxjs';

import { DialogComponent } from '@app/shared';
import { ListResult } from '../list/list.component';
import { ListService } from './list.service';
import { ListDirective } from '@app/abstract-directives/list.directive';
import { AdwpListDirective } from '@app/abstract-directives/adwp-list.directive';
import { IHost } from '@app/models/host';
import { ApiService } from '@app/core/api';
import { ICluster } from '@app/models/cluster';

interface IRowHost extends AdcmHost {
  clusters: Partial<Cluster>[];
  page: number;
}

export class BaseListDirective {

  socket$: Observable<any>;
  destroy$ = new Subject();

  row: Entities;
  listParams: ParamMap;
  limit = 10;
  typeName: TypeName;

  reload: (result: ListResult<Entities>) => void;

  constructor(
    private parent: ListDirective,
    private service: ListService,
    protected store: Store<SocketState>,
    private api: ApiService,
  ) {}

  takeUntil<T>() {
    return takeUntil<T>(this.destroy$);
  }

  startListenSocket(): void {
    this.socket$.pipe(tap(m => this.socketListener(m))).subscribe();
  }

  initSocket() {
    this.socket$ = this.store.pipe(this.takeUntil(), select(getMessage), filter(m => !!m && !!m.object));
  }

  initColumns() {
    this.parent.columns = this.service.initInstance(this.typeName).columns;
  }

  initListItemEvent() {
    this.parent.listItemEvt
      .pipe(this.takeUntil())
      .subscribe({ next: (event: EmmitRow) => this.listEvents(event) });
  }

  calcSort(ordering: string): Sort {
    let sort: Sort;
    if (ordering) {
      sort = {
        direction: ordering[0] === '-' ? 'desc' : 'asc',
        active: ordering[0] === '-' ? ordering.substr(1) : ordering,
      };
    }

    return sort;
  }

  routeListener(limit: number, page: number, ordering: string, params: ParamMap) {
    this.parent.paginator.pageSize = limit;
    if (page === 0) {
      this.parent.paginator.firstPage();
    } else {
      this.parent.paginator.pageIndex = page;
    }
    if (ordering && !this.parent.sort.active) {
      this.parent.sort.direction = ordering[0] === '-' ? 'desc' : 'asc';
      this.parent.sort.active = ordering[0] === '-' ? ordering.substr(1) : ordering;
      this.parent.sortParam = ordering;
    }

    this.listParams = params;
    this.refresh();
  }

  initRouteListener() {
    this.parent.route.paramMap
      .pipe(
        this.takeUntil(),
        filter((p) => this.checkParam(p))
      )
      .subscribe((p) => this.routeListener(+p.get('limit') || 10, +p.get('page'), p.get('ordering'), p));
  }

  init(): void {
    this.initSocket();
    this.initColumns();
    this.initListItemEvent();
    this.initRouteListener();
    this.startListenSocket();
  }

  destroy() {
    this.parent.listItemEvt.complete();

    this.destroy$.next();
    this.destroy$.complete();

    this.store.dispatch(clearMessages());
  }

  checkParam(p: ParamMap): boolean {
    const listParamStr = localStorage.getItem('list:param');
    if (!p.keys.length && listParamStr) {
      const json = JSON.parse(listParamStr);
      if (json[this.typeName]) {
        this.parent.router.navigate(['./', json[this.typeName]], { relativeTo: this.parent.route });
        return false;
      }
    }
    return true;
  }

  socketListener(m: EventMessage): void {
    const stype = (x: string) => `${m.object.type}${m.object.details.type ? `2${m.object.details.type}` : ''}` === x;
    const ctype = (name: string) => (name ? name.split('2')[0] : name) === m.object.type;

    const checkUpgradable = () => (m.event === 'create' || m.event === 'delete') && m.object.type === 'bundle' && this.typeName === 'cluster';
    const changeList = () => stype(this.typeName) && (m.event === 'create' || m.event === 'delete' || m.event === 'add' || m.event === 'remove');
    const createHostPro = () => stype('host2provider') && m.event === 'create';

    const rewriteRow = (row: Entities) => this.service.checkItem(row).subscribe((item) => Object.keys(row).map((a) => (row[a] = item[a])));

    if (checkUpgradable() || changeList() || createHostPro()) {
      this.refresh(m.object.id);
      return;
    }

    // events for the row of list
    if (this.parent.data.data.length) {
      const row = this.parent.data.data.find((a) => a.id === m.object.id);
      if (!row) return;

      if (m.event === 'add' && stype('host2cluster')) rewriteRow(row);

      if (ctype(this.typeName)) {
        if (m.event === 'change_state') row.state = m.object.details.value;
        if (m.event === 'change_status') row.status = +m.object.details.value;
        if (m.event === 'change_job_status') row.status = m.object.details.value;
        if (m.event === 'upgrade') rewriteRow(row);
      }
    }
  }

  refresh(id?: number) {
    if (id) this.parent.current = { id };
    this.service.getList(this.listParams, this.typeName).subscribe((list: IListResult<Entities>) => {
      if (this.reload) {
        this.reload(list);
      }
      this.parent.dataSource = list;
    });
  }

  listEvents(event: EmmitRow) {
    const createUrl = (a: string[]) => this.parent.router.createUrlTree(['./', this.row.id, ...a], { relativeTo: this.parent.route });
    const nav = (a: string[]) => this.parent.router.navigateByUrl(createUrl(a));

    this.row = event.row;
    const { cmd, item } = event;

    if (['title', 'status', 'config', 'import'].includes(cmd)) {
      nav(cmd === 'title' ? [] : [cmd]);
    } else if (cmd === 'new-tab') {
      const url = this.parent.router.serializeUrl(createUrl([]));
      window.open(url, '_blank');
    } else {
      this[cmd](item);
    }
  }

  onLoad() {}

  // getActions() {
  //   this.row.typeName = this.typeName;
  //   this.service.getActions(this.row);
  //   // this.parent.dialog.open(DialogComponent, { data: { title: 'Choose action', model: this.row, component: ActionCardComponent } });
  // }

  addCluster(id: number) {
    if (id) {
      this.service.addClusterToHost(id, this.row as AdcmHost)
        .subscribe((host) => {
          if ((this.parent as AdwpListDirective<IHost>)?.data$?.value?.results) {
            this.api.getOne('cluster', host.cluster_id).subscribe((cluster: ICluster) => {
              const tableData = Object.assign({}, (this.parent as AdwpListDirective<IHost>).data$.value);
              const index = tableData.results.findIndex(item => item.id === host.id);
              const row = Object.assign({}, tableData.results[index]);

              row.cluster_id = cluster.id;
              row.cluster_name = cluster.name;

              tableData.results.splice(index, 1, row);
              (this.parent as AdwpListDirective<IHost>).reload(tableData as IListResult<any>);
            });
          }
        });
    }
  }

  license() {
    const row = this.row as Bundle;

    const closedDialog$ = (text: string, dialog: MatDialog) =>
      dialog
        .open(DialogComponent, {
          data: {
            title: `Accept license agreement`,
            text,
            controls: { label: 'Do you accept the license agreement?', buttons: ['Yes', 'No'] },
          },
        })
        .beforeClosed();

    const showDialog = (info: { text: string }) =>
      closedDialog$(info.text, this.parent.dialog).pipe(
        filter((yes) => yes),
        switchMap(() => this.service.acceptLicense(`${row.license_url}accept/`).pipe(tap((_) => (row.license = 'accepted'))))
      );

    this.service.getLicenseInfo(row.license_url).pipe(this.takeUntil(), mergeMap(showDialog)).subscribe();
  }

  delete() {
    this.service
      .delete(this.row)
      .pipe(this.takeUntil())
      .subscribe(() => (this.parent.current = null));
  }

  // host
  getClusters() {
    const row = this.row as IRowHost;
    if (!row.clusters) {
      row.page = 0;
      this.service
        .getClustersForHost({ limit: this.limit, page: 0 })
        .pipe(this.takeUntil())
        .subscribe((list) => (row.clusters = list));
    }
  }

  getNextPageCluster() {
    const row = this.row as IRowHost;
    const count = row.clusters.length;
    if (count === (row.page + 1) * this.limit) {
      row.page++;
      this.service
        .getClustersForHost({ limit: this.limit, page: row.page })
        .pipe(this.takeUntil())
        .subscribe((list) => (row.clusters = [...row.clusters, ...list]));
    }
  }
}
