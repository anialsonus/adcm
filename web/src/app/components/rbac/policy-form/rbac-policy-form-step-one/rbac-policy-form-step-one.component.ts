import { Component, Input } from '@angular/core';
import { BaseFormDirective } from '../../../../shared/add-component';
import { FormGroup } from '@angular/forms';
import { ADWP_DEFAULT_MATCHER, AdwpMatcher } from '@adwp-ui/widgets';

@Component({
  selector: 'app-rbac-policy-form-step-one',
  templateUrl: './rbac-policy-form-step-one.component.html',
  styleUrls: ['./rbac-policy-form-step-one.component.scss']
})
export class RbacPolicyFormStepOneComponent extends BaseFormDirective {
  roleFilter = '';
  userFilter = '';
  groupFilter = '';

  matcher: AdwpMatcher<any> = ADWP_DEFAULT_MATCHER;

  @Input()
  form: FormGroup;

  isError(name: string): boolean {
    const f = this.form.get(name);
    return f.invalid && (f.dirty || f.touched);
  }

  hasError(error: string): boolean {
    return this.form.hasError(error);
  }
}
