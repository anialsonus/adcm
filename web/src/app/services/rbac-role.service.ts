import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@app/core/api';
import { environment } from '@env/environment';
import { EntityAbstractService } from '@app/abstract/entity.abstract.service';
import { FormModel } from '@app/shared/add-component/add-service-model';
import { RbacRoleModel } from '@app/models/rbac/rbac-role.model';
import { Params } from '@angular/router';
import { ListResult } from '@app/models/list-result';
import { map } from 'rxjs/operators';

@Injectable()
export class RbacRoleService implements EntityAbstractService {
  constructor(protected api: ApiService) {}

  model(value?: any): FormModel {
    return {
      name: 'role',
      value: value
    };
  }

  delete(id: number): Observable<unknown> {
    return this.api.delete(`${environment.apiRoot}rbac/role/${id}/`);
  }

  add(group: Partial<RbacRoleModel>): Observable<RbacRoleModel> {
    const params = { ...group };

    return this.api.post<RbacRoleModel>(`${environment.apiRoot}rbac/role/`, params);
  }

  update(url: string, params: Partial<RbacRoleModel>): Observable<RbacRoleModel> {
    return this.api.put<RbacRoleModel>(url, params);
  }

  getList(param?: Params): Observable<RbacRoleModel[]> {
    return this.api.get<ListResult<RbacRoleModel>>(`${environment.apiRoot}rbac/role/`, param)
      .pipe(map((list) => list.results));
  }
}
