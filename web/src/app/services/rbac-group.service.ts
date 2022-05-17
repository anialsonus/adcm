import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

import { ApiService } from '@app/core/api';
import { environment } from '@env/environment';
import { EntityAbstractService } from '@app/abstract/entity.abstract.service';
import { FormModel } from '@app/shared/add-component/add-service-model';
import { RbacGroupModel } from '@app/models/rbac/rbac-group.model';
import { Params } from '@angular/router';
import { ListResult } from '@app/models/list-result';
import { map } from 'rxjs/operators';

@Injectable()
export class RbacGroupService implements EntityAbstractService {
  constructor(protected api: ApiService) {}

  model(value?: any): FormModel {
    return {
      name: 'Group',
      value: value
    };
  }

  delete(id: number): Observable<any> {
    return this.api.delete(`${environment.apiRoot}rbac/group/${id}/`);
  }

  add(group: Partial<RbacGroupModel>): Observable<RbacGroupModel> {
    const params = { ...group };

    return this.api.post<RbacGroupModel>(`${environment.apiRoot}rbac/group/`, params);
  }

  update(url: string, params: Partial<RbacGroupModel>): Observable<RbacGroupModel> {
    return this.api.put<RbacGroupModel>(url, params);
  }

  getByUrl(url: string, params?: Params): Observable<RbacGroupModel> {
    const p = { expand: 'user', ...params };

    return this.api.get(url, p);
  }

  getList(param?: Params): Observable<RbacGroupModel[]> {
    return this.api.get<ListResult<RbacGroupModel>>(`${environment.apiRoot}rbac/group/`, param)
      .pipe(map((list) => list.results));
  }

}
