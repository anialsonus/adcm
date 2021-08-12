import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { CompareConfig, IConfig } from '../types';
import { map, switchMap } from 'rxjs/operators';
import { getRandomColor } from '@app/core/types';
import { ApiService } from '@app/core/api';
import { ClusterService } from '@app/core/services/cluster.service';
import { ConfigComponentEvents } from '@app/shared/configuration/services/events.service';
import { ConfigGroupsService } from '@app/shared/configuration/services/config-groups.service';

export interface IConfigResponse {
  current: string;
  history: string;
  previous: string;
}

export interface IConfigListResponse {
  count: 1;
  next: null;
  previous: null;
  results: IConfig[];
}


export interface IConfigService {
  getConfig(url: string): Observable<IConfig>;

  getHistoryList(url: string, currentVersionId: number): Observable<CompareConfig[]>

  send(url: string, data: any): Observable<IConfig>
}

@Injectable({
  providedIn: 'root'
})
export class ConfigService implements IConfigService {
  constructor(private api: ApiService,
              public cluster: ClusterService,
              public events: ConfigComponentEvents,
              public groups: ConfigGroupsService) { }

  getConfig(url: string): Observable<IConfig> {
    return this.api.get<IConfigResponse>(url).pipe(
      switchMap((config) => this.api.get<IConfig>(config.current))
    );
  }

  getHistoryList(url: string, currentVersionId: number): Observable<CompareConfig[]> {
    return this.api.get<IConfigResponse>(url).pipe(
      switchMap((config) => this.api.get<IConfigListResponse | IConfig[]>(config.history)),
      // ToDo remove it when API will be consistent
      map((value) => Array.isArray(value) ? value as IConfig[] : value.results),
      map((h) => h.filter((a) => a.id !== currentVersionId).map((b) => ({
        ...b,
        color: getRandomColor()
      }))));
  }

  send(url: string, data: any): Observable<IConfig> {
    return this.api.post<IConfig>(url, data);
  }
}
