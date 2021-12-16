import { Directive, Inject, Input } from '@angular/core';
import { AdwpHandler, AdwpStringHandler } from '@adwp-ui/widgets';
import { RbacRoleModel, RbacRoleType } from '../../../../models/rbac/rbac-role.model';
import { Params } from '@angular/router';
import { RbacOptionsDirective } from '../../../../abstract-directives/rbac-options.directive';
import { RbacRoleService } from '../../../../services/rbac-role.service';

@Directive({
  selector: '[appRbacRolesAsOptions], [rbac-roles-as-options]',
  exportAs: 'rbacRoles'
})
export class RbacRolesAsOptionsDirective extends RbacOptionsDirective {
  @Input('rbac-roles-as-options')
  params: Params;

  @Input('rbac-role-type')
  set type(value: RbacRoleType) {
    this.updateParam('type', value);
  };

  id: AdwpStringHandler<RbacRoleModel> = (item: RbacRoleModel) => String(item.id);

  label: AdwpStringHandler<RbacRoleModel> = (item: RbacRoleModel) => item.name;

  category: AdwpHandler<RbacRoleModel, string[]> = (item: RbacRoleModel) => item.category;

  constructor(@Inject(RbacRoleService) public service: RbacRoleService) {
    super(service);
  }
}
