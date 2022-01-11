import { Component, forwardRef, OnInit } from '@angular/core';
import { AbstractControl, FormArray, FormControl, FormGroup, Validators } from '@angular/forms';
import { RbacFormDirective } from '@app/shared/add-component/rbac-form.directive';
import { RbacPolicyModel } from '@app/models/rbac/rbac-policy.model';
import { ADD_SERVICE_PROVIDER } from '@app/shared/add-component/add-service-model';
import { RbacPolicyService } from '@app/services/rbac-policy.service';
import { atLeastOne } from '@app/components/rbac/policy-form/rbac-policy-form-step-one/validators/user-or-group-required';
import {
  IRbacObjectCandidateClusterModel,
  IRbacObjectCandidateHostModel,
  IRbacObjectCandidateProviderModel,
  IRbacObjectCandidateServiceModel
} from '../../../models/rbac/rbac-object-candidate';
import { rbacPolicyObjectValidator } from './validators/object-validator';
import { onlyOne } from './validators/provider-or-host';

const INITIAL_OBJECT = {
  cluster: [],
  parent: [],
  service: null,
  provider: [],
  host: []
};

@Component({
  selector: 'app-rbac-policy-form',
  templateUrl: './rbac-policy-form.component.html',
  providers: [
    { provide: ADD_SERVICE_PROVIDER, useExisting: forwardRef(() => RbacPolicyService) }
  ]
})
export class RbacPolicyFormComponent extends RbacFormDirective<RbacPolicyModel> implements OnInit {
  initialObject = INITIAL_OBJECT;

  /** Returns a FormArray with the name 'steps'. */
  get steps(): AbstractControl | null { return this.form.get('steps'); }

  step(id: number): FormGroup | null {
    return this.steps.get([id]) as FormGroup;
  }

  ngOnInit() {
    this._createForm();
    this._fillForm(this.value);
    this.form.markAllAsTouched();
  }

  rbacBeforeSave(value): RbacPolicyModel {
    const object = (value.steps[1] && value.steps[1].object) || {};

    const { cluster = [], parent = [], provider = [], host = [] } = object;

    return {
      ...value.steps[0],
      object: [
        ...cluster,
        ...parent,
        ...provider,
        ...host
      ]
    };
  }

  private _fillForm(value: RbacPolicyModel) {
    if (value) {
      this.form.setValue({
        steps: [
          {
            name: value.name,
            description: value.description || '',
            role: value.role,
            user: value.user,
            group: value.group
          },
          {
            object: {
              cluster: value.object.filter((item: IRbacObjectCandidateClusterModel) => item.type === 'cluster'),
              parent: [],
              service: value.object.find((item: IRbacObjectCandidateServiceModel) => item.type === 'service'),
              provider: value.object.filter((item: IRbacObjectCandidateProviderModel) => item.type === 'provider'),
              host: value.object.filter((item: IRbacObjectCandidateHostModel) => item.type === 'host'),
            }
          }
        ]
      });
    }
  }

  private _createForm(): void {
    const roleControl = new FormControl(null, [Validators.required]);

    this.form = new FormGroup({
      steps: new FormArray([
        new FormGroup({
          name: new FormControl(null, [Validators.required]),
          description: new FormControl(null),
          role: roleControl,
          user: new FormControl([]),
          group: new FormControl([])
        }, {
          validators: [atLeastOne('user', 'group')]
        }),
        new FormGroup({
          object: new FormGroup({
            cluster: new FormControl(null, [Validators.required]),
            parent: new FormControl(null, [Validators.required]),
            service: new FormControl(null, [Validators.required]),
            provider: new FormControl(null, [Validators.required]),
            host: new FormControl(null, [Validators.required]),
          }, {
            validators: [
              rbacPolicyObjectValidator(roleControl),
              onlyOne('host', 'provider'),
            ]
          })
        })
      ])
    });
  }
}
