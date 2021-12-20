import { Component, forwardRef } from '@angular/core';
import { AbstractControl, FormControl, FormGroup, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { RbacFormDirective } from '@app/shared/add-component/rbac-form.directive';
import { ADD_SERVICE_PROVIDER } from '@app/shared/add-component/add-service-model';
import { RbacUserService } from '@app/services/rbac-user.service';
import { RbacUserModel } from '@app/models/rbac/rbac-user.model';

/** The password and the confirm password must be equals  */
export const passwordsConfirmValidator: ValidatorFn = (control: AbstractControl): ValidationErrors | null => {
  const password = control.get('user')?.get('password');
  const confirm = control.get('confirm')?.get('password');

  return password && confirm && password.value !== confirm.value ? { passwordsNotMatch: true } : null;
};

@Component({
  selector: 'app-rbac-user-form',
  templateUrl: './rbac-user-form.component.html',
  providers: [
    { provide: ADD_SERVICE_PROVIDER, useExisting: forwardRef(() => RbacUserService) }
  ],
  styles: ['.rbac-user-form__password { display: flex; gap: 5px } .rbac-user-form__password > adwp-input { flex: 1 }']
})
export class RbacUserFormComponent extends RbacFormDirective<RbacUserModel> {
  private _isFirstTouch = true;

  get userForm(): FormGroup {
    return this.form.get('user') as FormGroup;
  }

  get confirmForm(): FormGroup {
    return this.form.get('confirm') as FormGroup;
  }

  form = new FormGroup({
    user: new FormGroup({
      id: new FormControl(null),
      is_superuser: new FormControl(null),
      url: new FormControl(null),
      profile: new FormControl(null),
      username: new FormControl(null, [Validators.required]),
      password: new FormControl(null, [
        Validators.required, Validators.min(5)
      ]),
      first_name: new FormControl(null, [Validators.required]),
      last_name: new FormControl(null, [Validators.required]),
      email: new FormControl(null, [Validators.required, Validators.email]),
      group: new FormControl([])
    }),
    confirm: new FormGroup({
      password: new FormControl('', [
        Validators.required, Validators.min(5)])
    })
  }, { validators: passwordsConfirmValidator });

  ngOnInit(): void {
    this._setValue(this.value);
    this._initPasswordConfirmSubscription();
  }

  rbacBeforeSave(value: any): Partial<RbacUserModel> {
    return value.user;
  }

  /**
   * As soon as a user focuses an input with password or an input of password confirmation,
   * then in this case we delete the dummy (*****) text
   */
  clearPasswordControlIfFocusIn(): void {
    const forms = Object.values(this.form.controls);

    forms.forEach((form) => {
      if (this._isFirstTouch) {
        form.get('password').setValue('');
        form.updateValueAndValidity();
      }
    });

    this._isFirstTouch = false;
  }

  /**
   * Need to set form value and form value to confirm password
   *
   * @param value
   * @private
   */
  private _setValue(value: RbacUserModel): void {
    if (value) {
      // ToDo(lihih) the "adwp-list" should not change the composition of the original model.
      //  Now he adds the "checked" key to the model
      delete this.value['checked'];
      this.form.get('user.username').disable();
      this.userForm.setValue(this.value);
      this.confirmForm.setValue({ password: this.value.password });
    }
  }

  /**
   * Our adwp-input does not know how to work with nested forms, therefore, in this case,
   * it does not display an error message if the control with the password is "invalid".
   * Therefore, we need to manually install and remove the desired error message.
   *
   * @private
   */
  private _initPasswordConfirmSubscription(): void {
    const controls = [this.userForm.get('password'), this.confirmForm.get('password')];

    this.form.statusChanges.subscribe(_ => {
      if (this.form.errors && this.form.errors.passwordsNotMatch) {
        controls.forEach((control) => {
          control.setErrors({ passwordsNotMatch: true }, { emitEvent: false });
        });
      } else {
        controls.forEach((control) => {
          control.setErrors({}, { emitEvent: false });
          control.updateValueAndValidity({ emitEvent: false });
        });
      }
    });
  }
}
